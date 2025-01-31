/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_SOCKET_COMPONENT_HPP__
#define __ASIO2_SOCKET_COMPONENT_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <string>

#include <asio2/external/asio.hpp>

namespace asio2::detail
{
	template<class derived_t, class args_t>
	class socket_cp
	{
	public:
		using socket_type = std::remove_cv_t<std::remove_reference_t<typename args_t::socket_t>>;

		/**
		 * @brief constructor
		 * @throws maybe throw exception "Too many open files" (exception code : 24)
		 * asio::error::no_descriptors - Too many open files
		 */
		template<class ...Args>
		explicit socket_cp(Args&&... args) : socket_(std::forward<Args>(args)...)
		{
		}

		/**
		 * @brief destructor
		 */
		~socket_cp() = default;

	public:
		/**
		 * @brief get the socket object refrence
		 */
		inline socket_type & socket() noexcept
		{
			return this->socket_;
		}

		/**
		 * @brief get the stream object refrence
		 */
		inline socket_type & stream() noexcept
		{
			return this->socket_;
		}

		/**
		 * @brief get the local address, same as get_local_address
		 */
		inline std::string local_address() noexcept
		{
			return this->get_local_address();
		}

		/**
		 * @brief get the local address
		 */
		inline std::string get_local_address() noexcept
		{
			try
			{
				return this->socket_.lowest_layer().local_endpoint().address().to_string();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return std::string();
		}

		/**
		 * @brief get the local port, same as get_local_port
		 */
		inline unsigned short local_port() noexcept
		{
			return this->get_local_port();
		}

		/**
		 * @brief get the local port
		 */
		inline unsigned short get_local_port() noexcept
		{
			try
			{
				return this->socket_.lowest_layer().local_endpoint().port();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return static_cast<unsigned short>(0);
		}

		/**
		 * @brief get the remote address, same as get_remote_address
		 */
		inline std::string remote_address() noexcept
		{
			return this->get_remote_address();
		}

		/**
		 * @brief get the remote address
		 */
		inline std::string get_remote_address() noexcept
		{
			try
			{
				return this->socket_.lowest_layer().remote_endpoint().address().to_string();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return std::string();
		}

		/**
		 * @brief get the remote port, same as get_remote_port
		 */
		inline unsigned short remote_port() noexcept
		{
			return this->get_remote_port();
		}

		/**
		 * @brief get the remote port
		 */
		inline unsigned short get_remote_port() noexcept
		{
			try
			{
				return this->socket_.lowest_layer().remote_endpoint().port();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return static_cast<unsigned short>(0);
		}

	public:
		/**
		 * @brief Implements the SOL_SOCKET/SO_SNDBUF socket option.
		 */
		inline derived_t & set_sndbuf_size(int val) noexcept
		{
			try
			{
				this->socket_.lowest_layer().set_option(asio::socket_base::send_buffer_size(val));
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t &>(*this));
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_SNDBUF socket option.
		 */
		inline int get_sndbuf_size() const noexcept
		{
			try
			{
				asio::socket_base::send_buffer_size option;
				this->socket_.lowest_layer().get_option(option);
				return option.value();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (-1);
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_RCVBUF socket option.
		 */
		inline derived_t & set_rcvbuf_size(int val) noexcept
		{
			try
			{
				this->socket_.lowest_layer().set_option(asio::socket_base::receive_buffer_size(val));
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t &>(*this));
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_RCVBUF socket option.
		 */
		inline int get_rcvbuf_size() const noexcept
		{
			try
			{
				asio::socket_base::receive_buffer_size option;
				this->socket_.lowest_layer().get_option(option);
				return option.value();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (-1);
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_KEEPALIVE socket option. same as set_keep_alive
		 */
		inline derived_t & keep_alive(bool val) noexcept
		{
			return this->set_keep_alive(val);
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_KEEPALIVE socket option.
		 */
		inline derived_t & set_keep_alive(bool val) noexcept
		{
			try
			{
				this->socket_.lowest_layer().set_option(asio::socket_base::keep_alive(val));
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t &>(*this));
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_KEEPALIVE socket option.
		 */
		inline bool is_keep_alive() const noexcept
		{
			try
			{
				asio::socket_base::keep_alive option;
				this->socket_.lowest_layer().get_option(option);
				return option.value();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return false;
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_REUSEADDR socket option. same as set_reuse_address
		 */
		inline derived_t & reuse_address(bool val) noexcept
		{
			return this->set_reuse_address(val);
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_REUSEADDR socket option.
		 */
		inline derived_t & set_reuse_address(bool val) noexcept
		{
			try
			{
				this->socket_.lowest_layer().set_option(asio::socket_base::reuse_address(val));
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t &>(*this));
		}

		/**
		 * @brief Implements the SOL_SOCKET/SO_REUSEADDR socket option.
		 */
		inline bool is_reuse_address() const noexcept
		{
			try
			{
				asio::socket_base::reuse_address option;
				this->socket_.lowest_layer().get_option(option);
				return option.value();
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return false;
		}

		/**
		 * @brief Implements the TCP_NODELAY socket option. same as set_no_delay.
		 * If it's not a tcp socket, do nothing
		 */
		inline derived_t & no_delay(bool val) noexcept
		{
			return this->set_no_delay(val);
		}

		/**
		 * @brief Implements the TCP_NODELAY socket option.
		 * If it's not a tcp socket, do nothing
		 */
		inline derived_t & set_no_delay(bool val) noexcept
		{
			try
			{
				if constexpr (std::is_same_v<typename socket_type::protocol_type, asio::ip::tcp>)
				{
					this->socket_.lowest_layer().set_option(asio::ip::tcp::no_delay(val));
				}
				else
				{
					std::ignore = val;
					//static_assert(false, "Only tcp socket has the no_delay option");
				}
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t &>(*this));
		}

		/**
		 * @brief Implements the TCP_NODELAY socket option.
		 */
		inline bool is_no_delay() const noexcept
		{
			try
			{
				if constexpr (std::is_same_v<typename socket_type::protocol_type, asio::ip::tcp>)
				{
					asio::ip::tcp::no_delay option;
					this->socket_.lowest_layer().get_option(option);
					return option.value();
				}
				else
				{
					std::ignore = true;
					//static_assert(false, "Only tcp socket has the no_delay option");
				}
			}
			catch (system_error & e)
			{
				set_last_error(e);
			}
			return false;
		}

		/**
		 * @brief Implements the SO_LINGER socket option.
		 *        set_linger(true, 0) - RST will be sent instead of FIN/ACK/FIN/ACK
		 * @param enable - option on/off
		 * @param timeout - linger time
		 */
		inline derived_t& set_linger(bool enable, int timeout) noexcept
		{
			try
			{
				this->socket_.lowest_layer().set_option(asio::socket_base::linger(enable, timeout));
			}
			catch (system_error& e)
			{
				set_last_error(e);
			}
			return (static_cast<derived_t&>(*this));
		}

		/**
		 * @brief Get the SO_LINGER socket option.
		 */
		inline asio::socket_base::linger get_linger() const noexcept
		{
			asio::socket_base::linger option{};
			try
			{
				this->socket_.lowest_layer().get_option(option);
			}
			catch (system_error& e)
			{
				set_last_error(e);
			}
			return option;
		}

	protected:
		/// socket 
		typename args_t::socket_t socket_;
	};
}

#endif // !__ASIO2_SOCKET_COMPONENT_HPP__
