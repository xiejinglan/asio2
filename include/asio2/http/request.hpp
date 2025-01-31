/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_HTTP_REQUEST_IMPL_HPP__
#define __ASIO2_HTTP_REQUEST_IMPL_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <asio2/base/detail/push_options.hpp>

#include <asio2/base/component/user_data_cp.hpp>

#include <asio2/http/detail/http_util.hpp>
#include <asio2/http/detail/http_url.hpp>

#ifdef ASIO2_HEADER_ONLY
namespace bho::beast::websocket
#else
namespace boost::beast::websocket
#endif
{
	template <class> class listener;
}

namespace asio2::detail
{
	ASIO2_CLASS_FORWARD_DECLARE_BASE;
	ASIO2_CLASS_FORWARD_DECLARE_TCP_BASE;
	ASIO2_CLASS_FORWARD_DECLARE_TCP_CLIENT;
	ASIO2_CLASS_FORWARD_DECLARE_TCP_SESSION;

	template<class Body, class Fields = http::fields>
	class http_request_impl_t
		: public http::message<true, Body, Fields>
#ifndef ASIO2_DISABLE_HTTP_REQUEST_USER_DATA_CP
		, public user_data_cp<http_request_impl_t<Body, Fields>>
#endif
	{
		template <class>                             friend class beast::websocket::listener;

		ASIO2_CLASS_FRIEND_DECLARE_BASE;
		ASIO2_CLASS_FRIEND_DECLARE_TCP_BASE;
		ASIO2_CLASS_FRIEND_DECLARE_TCP_CLIENT;
		ASIO2_CLASS_FRIEND_DECLARE_TCP_SESSION;

	public:
		using self  = http_request_impl_t<Body, Fields>;
		using super = http::message<true, Body, Fields>;
		using header_type = typename super::header_type;
		using body_type = typename super::body_type;

	public:
		/**
		 * @brief constructor
		 */
		template<typename... Args>
		explicit http_request_impl_t(Args&&... args)
			: super(std::forward<Args>(args)...)
			, user_data_cp<http_request_impl_t<Body, Fields>>()
		{
		}

		http_request_impl_t(const http_request_impl_t& o)
			: super()
			, user_data_cp<http_request_impl_t<Body, Fields>>()
		{
			this->base() = o.base();
			this->url_           = o.url_;
			this->ws_frame_type_ = o.ws_frame_type_;
			this->ws_frame_data_ = o.ws_frame_data_;
		}

		http_request_impl_t(http_request_impl_t&& o)
			: super()
			, user_data_cp<http_request_impl_t<Body, Fields>>()
		{
			this->base() = std::move(o.base());
			this->url_           = std::move(o.url_);
			this->ws_frame_type_ = o.ws_frame_type_;
			this->ws_frame_data_ = o.ws_frame_data_;
		}

		self& operator=(const http_request_impl_t& o)
		{
			this->base() = o.base();
			this->url_           = o.url_;
			this->ws_frame_type_ = o.ws_frame_type_;
			this->ws_frame_data_ = o.ws_frame_data_;
			return *this;
		}

		self& operator=(http_request_impl_t&& o)
		{
			this->base() = std::move(o.base());
			this->url_           = std::move(o.url_);
			this->ws_frame_type_ = o.ws_frame_type_;
			this->ws_frame_data_ = o.ws_frame_data_;
			return *this;
		}

		http_request_impl_t(const http::message<true, Body, Fields>& req)
			: super()
			, user_data_cp<http_request_impl_t<Body, Fields>>()
		{
			this->base() = req;
		}

		http_request_impl_t(http::message<true, Body, Fields>&& req)
			: super()
			, user_data_cp<http_request_impl_t<Body, Fields>>()
		{
			this->base() = std::move(req);
		}

		self& operator=(const http::message<true, Body, Fields>& req)
		{
			this->base() = req;
			return *this;
		}

		self& operator=(http::message<true, Body, Fields>&& req)
		{
			this->base() = std::move(req);
			return *this;
		}

		/**
		 * @brief destructor
		 */
		~http_request_impl_t()
		{
		}

		/// Returns the base portion of the message
		inline super const& base() const noexcept
		{
			return *this;
		}

		/// Returns the base portion of the message
		inline super& base() noexcept
		{
			return *this;
		}

		inline void reset()
		{
			static_cast<super&>(*this) = {};
		}

	public:
		/**
		 * @brief Returns `true` if this HTTP request is a WebSocket Upgrade.
		 */
		inline bool is_upgrade() noexcept { return websocket::is_upgrade(*this); }

		/**
		 * @brief Gets the content of the "schema" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 */
		inline std::string_view get_schema() noexcept
		{
			return this->url_.schema();
		}

		/**
		 * @brief Gets the content of the "schema" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 * same as get_schema
		 */
		inline std::string_view schema() noexcept
		{
			return this->get_schema();
		}

		/**
		 * @brief Gets the content of the "host" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 */
		inline std::string_view get_host() noexcept
		{
			return this->url_.host();
		}

		/**
		 * @brief Gets the content of the "host" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 * same as get_host
		 */
		inline std::string_view host() noexcept
		{
			return this->get_host();
		}

		/**
		 * @brief Gets the content of the "port" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 */
		inline std::string_view get_port() noexcept
		{
			return this->url_.port();
		}

		/**
		 * @brief Gets the content of the "port" section, maybe empty
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 * same as get_port
		 */
		inline std::string_view port() noexcept
		{
			return this->get_port();
		}

		/**
		 * @brief Gets the content of the "path" section of the target
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 */
		inline std::string_view get_path()
		{
			if (!this->url_.string().empty())
				return this->url_.path();

			if (!(this->url_.parser().field_set & (1 << (int)http::parses::url_fields::UF_PATH)))
				return std::string_view{ "/" };

			std::string_view target = this->target();

			return std::string_view{ &target[
				this->url_.parser().field_data[(int)http::parses::url_fields::UF_PATH].off],
				this->url_.parser().field_data[(int)http::parses::url_fields::UF_PATH].len };
		}

		/**
		 * @brief Gets the content of the "path" section of the target
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 * same as get_path
		 */
		inline std::string_view path()
		{
			return this->get_path();
		}

		/**
		 * @brief Gets the content of the "query" section of the target
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 */
		inline std::string_view get_query()
		{
			if (!this->url_.string().empty())
				return this->url_.query();

			if (!(this->url_.parser().field_set & (1 << (int)http::parses::url_fields::UF_QUERY)))
				return std::string_view{};

			std::string_view target = this->target();

			return std::string_view{ &target[
				this->url_.parser().field_data[(int)http::parses::url_fields::UF_QUERY].off],
				this->url_.parser().field_data[(int)http::parses::url_fields::UF_QUERY].len };
		}

		/**
		 * @brief Gets the content of the "query" section of the target
		 * <scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<fragment>
		 * same as get_query
		 */
		inline std::string_view query()
		{
			return this->get_query();
		}

		/**
		 * @brief Returns `true` if this HTTP request's Content-Type is "multipart/form-data";
		 */
		inline bool has_multipart() noexcept
		{
			return http::has_multipart(*this);
		}

		/**
		 * @brief Get the "multipart/form-data" body content.
		 */
		inline decltype(auto) get_multipart()
		{
			return http::multipart(*this);
		}

		/**
		 * @brief Get the "multipart/form-data" body content. same as get_multipart
		 */
		inline decltype(auto) multipart()
		{
			return this->get_multipart();
		}

		/**
		 * @brief Get the url object reference. same as get_url
		 */
		inline http::url&    url() { return this->url_; }

		/**
		 * @brief Get the url object reference.
		 */
		inline http::url& get_url() { return this->url_; }

	protected:
		http::url                             url_{ "" };
		websocket::frame                      ws_frame_type_ = websocket::frame::unknown;
		std::string_view                      ws_frame_data_;
	};
}

#ifdef ASIO2_HEADER_ONLY
namespace bho::beast::http
#else
namespace boost::beast::http
#endif
{
	using web_request = asio2::detail::http_request_impl_t<http::string_body>;
}

#include <asio2/base/detail/pop_options.hpp>

#endif // !__ASIO2_HTTP_REQUEST_IMPL_HPP__
