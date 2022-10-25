/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_KCP_STREAM_CP_HPP__
#define __ASIO2_KCP_STREAM_CP_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <asio2/base/iopool.hpp>
#include <asio2/base/define.hpp>
#include <asio2/base/listener.hpp>
#include <asio2/base/session_mgr.hpp>

#include <asio2/base/detail/object.hpp>
#include <asio2/base/detail/allocator.hpp>
#include <asio2/base/detail/util.hpp>
#include <asio2/base/detail/buffer_wrap.hpp>

#include <asio2/udp/detail/kcp_util.hpp>
#ifdef USE_KCP_FEC
#include "fec.h"
#include "encoding.h"
#endif

namespace asio2::detail
{
	ASIO2_CLASS_FORWARD_DECLARE_UDP_CLIENT;
	ASIO2_CLASS_FORWARD_DECLARE_UDP_SERVER;
	ASIO2_CLASS_FORWARD_DECLARE_UDP_SESSION;

	/*
	 * because udp is connectionless, in order to simplify the code logic, KCP shakes
	 * hands only twice (compared with TCP handshakes three times)
	 * 1 : client send syn to server
	 * 2 : server send synack to client
	 */
	template<class derived_t, class args_t>
	class kcp_stream_cp
	{
		friend derived_t; // C++11

		ASIO2_CLASS_FRIEND_DECLARE_UDP_CLIENT;
		ASIO2_CLASS_FRIEND_DECLARE_UDP_SERVER;
		ASIO2_CLASS_FRIEND_DECLARE_UDP_SESSION;

	public:
		/**
		 * @brief constructor
		 */
		kcp_stream_cp(derived_t& d, io_t& io)
			: derive(d), kcp_timer_(io.context())
		{
		}

		/**
		 * @brief destructor
		 */
		~kcp_stream_cp() noexcept
		{
			if (this->kcp_)
			{
				kcp::ikcp_release(this->kcp_);
				this->kcp_ = nullptr;
			}
		}

	protected:
		inline void _kcp_start(std::shared_ptr<derived_t> this_ptr, std::uint32_t conv)
		{
			// used to restore configs
			kcp::ikcpcb* old = this->kcp_;

			struct old_kcp_destructor
			{
				 old_kcp_destructor(kcp::ikcpcb* p) : p_(p) {}
				~old_kcp_destructor()
				{
					if (p_)
						kcp::ikcp_release(p_);
				}

				kcp::ikcpcb* p_ = nullptr;
			} old_kcp_destructor_guard(old);

			ASIO2_ASSERT(conv != 0);
#ifdef USE_KCP_FEC
            this->dataShards=3;
            this->parityShards=1;
            this->shards.resize(dataShards + parityShards, nullptr);
            this->fec = FEC::New(3 * (dataShards + parityShards), dataShards, parityShards);
#endif
			this->kcp_ = kcp::ikcp_create(conv, (void*)this);
			this->kcp_->output = &kcp_stream_cp<derived_t, args_t>::_kcp_output;

			if (old)
			{
				// ikcp_setmtu
				kcp::ikcp_setmtu(this->kcp_, old->mtu);

				// ikcp_wndsize
				kcp::ikcp_wndsize(this->kcp_, old->snd_wnd, old->rcv_wnd);

				// ikcp_nodelay
				kcp::ikcp_nodelay(this->kcp_, old->nodelay, old->interval, old->fastresend, old->nocwnd);
			}
			else
			{
				kcp::ikcp_nodelay(this->kcp_, 1, 10, 2, 1);
				kcp::ikcp_wndsize(this->kcp_, 128, 512);
			}

			// if call kcp_timer_.cancel first, then call _post_kcp_timer second immediately,
			// use asio::post to avoid start timer failed.
			asio::post(derive.io().context(), make_allocator(derive.wallocator(),
			[this, this_ptr = std::move(this_ptr)]() mutable
			{
				this->_post_kcp_timer(std::move(this_ptr));
			}));
		}

		inline void _kcp_stop()
		{
			error_code ec_ignore{};

#ifndef USE_KCP_FEC
            // if is kcp mode, send FIN handshake before close
			if (this->send_fin_)
				this->_kcp_send_hdr(kcp::make_kcphdr_fin(0), ec_ignore);
#endif

			try
			{
				this->kcp_timer_.cancel();
			}
			catch (system_error const&)
			{
			}
		}

	protected:
#ifndef USE_KCP_FEC
		inline std::size_t _kcp_send_hdr(kcp::kcphdr hdr, error_code& ec)
		{
			std::string msg = kcp::to_string(hdr);
			std::size_t sent_bytes = 0;
			if constexpr (args_t::is_session)
				sent_bytes = derive.stream().send_to(asio::buffer(msg), derive.remote_endpoint_, 0, ec);
			else
				sent_bytes = derive.stream().send(asio::buffer(msg), 0, ec);
			return sent_bytes;
		}

		inline std::size_t _kcp_send_syn(std::uint32_t seq, error_code& ec)
		{
			kcp::kcphdr syn = kcp::make_kcphdr_syn(derive.kcp_conv_, seq);
			return this->_kcp_send_hdr(syn, ec);
		}

		inline std::size_t _kcp_send_synack(kcp::kcphdr syn, error_code& ec)
		{
			// the syn.th_ack is the kcp conv
			kcp::kcphdr synack = kcp::make_kcphdr_synack(syn.th_ack, syn.th_seq);
			return this->_kcp_send_hdr(synack, ec);
		}
#endif
		template<class Data, class Callback>
		inline bool _kcp_send(Data& data, Callback&& callback)
		{
			auto buffer = asio::buffer(data);

			int ret = kcp::ikcp_send(this->kcp_, (const char *)buffer.data(), (int)buffer.size());
			switch (ret)
			{
			case  0: set_last_error(error_code{}                        ); break;
			case -1: set_last_error(asio::error::invalid_argument       ); break;
			case -2: set_last_error(asio::error::no_memory              ); break;
			default: set_last_error(asio::error::operation_not_supported); break;
			}
			if (ret == 0)
			{
				kcp::ikcp_flush(this->kcp_);
			}
			callback(get_last_error(), ret < 0 ? 0 : buffer.size());

			return (ret == 0);
		}

		inline void _post_kcp_timer(std::shared_ptr<derived_t> this_ptr)
		{
			std::uint32_t clock1 = static_cast<std::uint32_t>(std::chrono::duration_cast<
				std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
			std::uint32_t clock2 = kcp::ikcp_check(this->kcp_, clock1);

			this->kcp_timer_.expires_after(std::chrono::milliseconds(clock2 - clock1));
			this->kcp_timer_.async_wait(make_allocator(this->tallocator_,
			[this, self_ptr = std::move(this_ptr)](const error_code & ec) mutable
			{
				this->_handle_kcp_timer(ec, std::move(self_ptr));
			}));
		}

		inline void _handle_kcp_timer(const error_code & ec, std::shared_ptr<derived_t> this_ptr)
		{
			if (ec == asio::error::operation_aborted) return;

			std::uint32_t clock = static_cast<std::uint32_t>(std::chrono::duration_cast<
				std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
			kcp::ikcp_update(this->kcp_, clock);
			if (this->kcp_->state == (kcp::IUINT32)-1)
			{
				if (derive.state() == state_t::started)
				{
					derive._do_disconnect(asio::error::network_reset, std::move(this_ptr));
				}
				return;
			}
			if (derive.is_started())
				this->_post_kcp_timer(std::move(this_ptr));
		}

        template<class buffer_t, typename MatchCondition>
        inline void _do_kcp_recv(std::shared_ptr<derived_t>& this_ptr, std::string_view data, buffer_t& buffer,
                              condition_wrap<MatchCondition>& condition){
            int len = kcp::ikcp_input(this->kcp_, (const char *)data.data(), (long)data.size());
            buffer.consume(buffer.size());
            if (len != 0)
            {
                set_last_error(asio::error::message_size);
                if (derive.state() == state_t::started)
                {
                    derive._do_disconnect(asio::error::message_size, this_ptr);
                }
                return;
            }
            for (;;)
            {
                len = kcp::ikcp_recv(this->kcp_, (char *)buffer.prepare(
                        buffer.pre_size()).data(), (int)buffer.pre_size());
                if /**/ (len >= 0)
                {
                    buffer.commit(len);
                    derive._fire_recv(this_ptr, std::string_view(static_cast
                                                                         <std::string_view::const_pointer>(buffer.data().data()), len), condition);
                    buffer.consume(len);
                }
                else if (len == -3)
                {
                    buffer.pre_size(buffer.pre_size() * 2);
                }
                else break;
            }
            kcp::ikcp_flush(this->kcp_);
        }

		template<class buffer_t, typename MatchCondition>
		inline void _kcp_recv(std::shared_ptr<derived_t>& this_ptr, std::string_view data, buffer_t& buffer,
			condition_wrap<MatchCondition>& condition)
		{
#ifdef USE_KCP_FEC
            // decode FEC packet
            auto pkt = fec.Decode((byte *) data.data(), static_cast<size_t>(data.size()));
            if (pkt.flag == typeData) {
                auto ptr = pkt.data->data();

                std::string_view sv((char *) (ptr + 2),pkt.data->size() - 2);
                _do_kcp_recv(this_ptr,sv,buffer,condition);
            }

            // allow FEC packet processing with correct flags.
            if (pkt.flag == typeData || pkt.flag == typeFEC) {
                // input to FEC, and see if we can recover data.
                auto recovered = fec.Input(pkt);
                // we have some data recovered.
                for (auto &r : recovered) {
                    // recovered data has at least 2B size.
                    if (r->size() > 2) {
                        auto ptr = r->data();
                        // decode packet size, which is also recovered.
                        uint16_t sz;
                        decode16u(ptr, &sz);
                        // the recovered packet size must be in the correct range.
                        if (sz >= 2 && sz <= r->size()) {
                            std::string_view sv((char *) (ptr + 2),sz - 2);
                            _do_kcp_recv(this_ptr,sv,buffer,condition);

                        }
                    }
                }
            }
#else
            _do_kcp_recv(this_ptr,data,buffer,condition);
#endif
		}
#ifndef AUTO_CONFIG_CONV
		template<typename MatchCondition, typename DeferEvent>
		inline void _post_handshake(
			std::shared_ptr<derived_t> self_ptr, condition_wrap<MatchCondition> condition, DeferEvent chain)
		{
			try
			{
				error_code ec;
				if constexpr (args_t::is_session)
				{
					// step 3 : server recvd syn from client (the first_ is the syn)
					kcp::kcphdr syn = kcp::to_kcphdr(derive.first_);
					std::uint32_t conv = syn.th_ack;
					if (conv == 0)
					{
						conv = derive.kcp_conv_;
						syn.th_ack = conv;
					}

					// step 4 : server send synack to client
					this->_kcp_send_synack(syn, ec);

					asio::detail::throw_error(ec);

					this->_kcp_start(self_ptr, conv);
					this->_handle_handshake(ec, std::move(self_ptr), std::move(condition), std::move(chain));
				}
				else
				{
					// step 1 : client send syn to server
					std::uint32_t seq = static_cast<std::uint32_t>(
						std::chrono::duration_cast<std::chrono::milliseconds>(
						std::chrono::system_clock::now().time_since_epoch()).count());

					this->_kcp_send_syn(seq, ec);

					asio::detail::throw_error(ec);

					// use a loop timer to execute "client send syn to server" until the server
					// has recvd the syn packet and this client recvd reply.
					std::shared_ptr<asio::steady_timer> timer =
						mktimer(derive.io().context(), std::chrono::milliseconds(500),
						[this, self_ptr, seq](error_code ec) mutable
					{
						if (ec == asio::error::operation_aborted)
							return false;
						this->_kcp_send_syn(seq, ec);
						if (ec)
						{
							set_last_error(ec);
							if (derive.state() == state_t::started)
							{
								derive._do_disconnect(ec, std::move(self_ptr));
							}
							return false;
						}
						// return true  : let the timer continue execute.
						// return false : kill the timer.
						return true;
					});

					// step 2 : client wait for recv synack util connect timeout or recvd some data
					derive.socket().async_receive(derive.buffer().prepare(derive.buffer().pre_size()),
						make_allocator(derive.rallocator(),
					[this, seq, this_ptr = std::move(self_ptr), condition = std::move(condition),
						timer = std::move(timer), chain = std::move(chain)]
					(const error_code & ec, std::size_t bytes_recvd) mutable
					{
						ASIO2_ASSERT(derive.io().running_in_this_thread());

						try
						{
							timer->cancel();
						}
						catch (system_error const&)
						{
						}

						if (ec)
						{
							// if connect_timeout_timer_ is empty, it means that the connect timeout timer is
							// timeout and the callback has called already, so reset the error to timed_out.
							// note : when the async_resolve is failed, the socket is invalid to.
							this->_handle_handshake(
								derive.connect_timeout_timer_ ? ec : asio::error::timed_out,
								std::move(this_ptr), std::move(condition), std::move(chain));
							return;
						}

						derive.buffer().commit(bytes_recvd);

						std::string_view data = std::string_view(static_cast<std::string_view::const_pointer>
							(derive.buffer().data().data()), bytes_recvd);

						// Check whether the data is the correct handshake information
						if (kcp::is_kcphdr_synack(data, seq))
						{
							kcp::kcphdr hdr = kcp::to_kcphdr(data);
							std::uint32_t conv = hdr.th_seq;
							if (derive.kcp_conv_ != 0)
							{
								ASIO2_ASSERT(derive.kcp_conv_ == conv);
							}
							this->_kcp_start(this_ptr, conv);
							this->_handle_handshake(ec, std::move(this_ptr), std::move(condition), std::move(chain));
						}
						else
						{
							this->_handle_handshake(asio::error::address_family_not_supported,
								std::move(this_ptr), std::move(condition), std::move(chain));
						}

						derive.buffer().consume(bytes_recvd);
					}));
				}
			}
			catch (system_error & e)
			{
				set_last_error(e);

				if constexpr (args_t::is_session)
				{
					derive._do_disconnect(e.code(), derive.selfptr(), std::move(chain));
				}
				else
				{
					derive._do_disconnect(e.code(), derive.selfptr(), defer_event(chain.move_guard()));
				}
			}
		}
#else
        template<typename MatchCondition, typename DeferEvent>
        inline void _post_handshake(
                std::shared_ptr<derived_t> self_ptr, condition_wrap<MatchCondition> condition, DeferEvent chain)
        {
            error_code ec;
            this->_kcp_start(self_ptr, derive.kcp_conv_);
            this->_handle_handshake(ec, std::move(self_ptr), std::move(condition), std::move(chain));
        }
#endif
		template<typename MatchCondition, typename DeferEvent>
		inline void _handle_handshake(const error_code & ec, std::shared_ptr<derived_t> this_ptr,
			condition_wrap<MatchCondition> condition, DeferEvent chain)
		{
			set_last_error(ec);

			try
			{
				if constexpr (args_t::is_session)
				{
					derive._fire_handshake(this_ptr);

					asio::detail::throw_error(ec);

					derive._done_connect(ec, std::move(this_ptr), std::move(condition), std::move(chain));
				}
				else
				{
					derive._fire_handshake(this_ptr);

					derive._done_connect(ec, std::move(this_ptr), std::move(condition), std::move(chain));
				}
			}
			catch (system_error & e)
			{
				set_last_error(e);

				derive._do_disconnect(e.code(), derive.selfptr(), defer_event(chain.move_guard()));
			}
		}

		static int _kcp_output(const char *buf, int len, kcp::ikcpcb *kcp, void *user)
		{
#ifdef USE_KCP_FEC
            auto t = (kcp_stream_cp*)user;
            derived_t & derive = t->derive;
            error_code ec;

            // append FEC header
            // extend to len + fecHeaderSizePlus2
            // i.e. 4B seqid + 2B flag + 2B size
            memcpy(t->m_buf + fecHeaderSizePlus2, buf, static_cast<size_t>(len));
            t->fec.MarkData(t->m_buf, static_cast<uint16_t>(len));



            if constexpr (args_t::is_session)
                derive.stream().send_to(asio::buffer(t->m_buf, len + fecHeaderSizePlus2),
                                        derive.remote_endpoint_, 0, ec);
            else
                derive.stream().send(asio::buffer(t->m_buf, len + fecHeaderSizePlus2), 0, ec);


            // FEC calculation
            // copy "2B size + data" to shards
            auto slen = len + 2;
            t->shards[t->pkt_idx] = std::make_shared<std::vector<byte>>(&t->m_buf[fecHeaderSize], &t->m_buf[fecHeaderSize + slen]);

            // count number of data shards
            t->pkt_idx++;
            if (t->pkt_idx == t->dataShards) { // we've collected enough data shards
                t->fec.Encode(t->shards);
                // send parity shards
                for (size_t i = t->dataShards; i < t->dataShards + t->parityShards; i++) {
                    // append header to parity shards
                    // i.e. fecHeaderSize + data(2B size included)
                    memcpy(t->m_buf + fecHeaderSize, t->shards[i]->data(), t->shards[i]->size());
                    t->fec.MarkFEC(t->m_buf);

                    if constexpr (args_t::is_session)
                        derive.stream().send_to(asio::buffer(t->m_buf, t->shards[i]->size() + fecHeaderSize),
                                                derive.remote_endpoint_, 0, ec);
                    else
                        derive.stream().send(asio::buffer(t->m_buf, t->shards[i]->size() + fecHeaderSize), 0, ec);

                }
                // reset indexing
                t->pkt_idx = 0;
            }
#else
            std::ignore = kcp;

			kcp_stream_cp * zhis = ((kcp_stream_cp*)user);

			derived_t & derive = zhis->derive;

			error_code ec;
			if constexpr (args_t::is_session)
				derive.stream().send_to(asio::buffer(buf, len),
					derive.remote_endpoint_, 0, ec);
			else
				derive.stream().send(asio::buffer(buf, len), 0, ec);
#endif


			return 0;
		}

	protected:
		derived_t                   & derive;

		kcp::ikcpcb                 * kcp_ = nullptr;
#ifdef USE_KCP_FEC
        FEC                          fec;
        uint32_t pkt_idx{0};
        std::vector<row_type> shards;
        size_t dataShards{0};
        size_t parityShards{0};
        byte m_buf[2048];
#endif
		bool                          send_fin_ = true;

		handler_memory<>              tallocator_;

		asio::steady_timer            kcp_timer_;
	};
}

#endif // !__ASIO2_KCP_STREAM_CP_HPP__
