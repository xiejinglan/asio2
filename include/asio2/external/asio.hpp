/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_ASIO_HPP__
#define __ASIO2_ASIO_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <asio2/config.hpp>

#ifdef ASIO2_HEADER_ONLY
#  ifndef ASIO_STANDALONE
#    define ASIO_STANDALONE
#  endif
#endif

#ifdef ASIO_STANDALONE
#  ifndef ASIO_HEADER_ONLY
#    define ASIO_HEADER_ONLY
#  endif
#endif

#include <asio2/base/detail/push_options.hpp>

#ifdef ASIO_STANDALONE
	#if   __has_include(<asio.hpp>)
		#include <asio.hpp>
	#elif __has_include(<asio/asio.hpp>)
		#include <asio/asio.hpp>
	#else
		#include "asio/associated_allocator.hpp"
		#include "asio/associated_executor.hpp"
		#include "asio/async_result.hpp"
		#include "asio/awaitable.hpp"
		#include "asio/basic_datagram_socket.hpp"
		#include "asio/basic_deadline_timer.hpp"
		#include "asio/basic_io_object.hpp"
		#include "asio/basic_raw_socket.hpp"
		#include "asio/basic_seq_packet_socket.hpp"
		#include "asio/basic_serial_port.hpp"
		#include "asio/basic_signal_set.hpp"
		#include "asio/basic_socket.hpp"
		#include "asio/basic_socket_acceptor.hpp"
		#include "asio/basic_socket_iostream.hpp"
		#include "asio/basic_socket_streambuf.hpp"
		#include "asio/basic_stream_socket.hpp"
		#include "asio/basic_streambuf.hpp"
		#include "asio/basic_waitable_timer.hpp"
		#include "asio/bind_executor.hpp"
		#include "asio/buffer.hpp"
		#include "asio/buffered_read_stream_fwd.hpp"
		#include "asio/buffered_read_stream.hpp"
		#include "asio/buffered_stream_fwd.hpp"
		#include "asio/buffered_stream.hpp"
		#include "asio/buffered_write_stream_fwd.hpp"
		#include "asio/buffered_write_stream.hpp"
		#include "asio/buffers_iterator.hpp"
		#include "asio/co_spawn.hpp"
		#include "asio/completion_condition.hpp"
		#include "asio/compose.hpp"
		#include "asio/connect.hpp"
		#include "asio/coroutine.hpp"
		#include "asio/deadline_timer.hpp"
		#include "asio/defer.hpp"
		#include "asio/detached.hpp"
		#include "asio/dispatch.hpp"
		#include "asio/error.hpp"
		#include "asio/error_code.hpp"
		#include "asio/execution.hpp"
		#include "asio/execution/allocator.hpp"
		#include "asio/execution/any_executor.hpp"
		#include "asio/execution/blocking.hpp"
		#include "asio/execution/blocking_adaptation.hpp"
		#include "asio/execution/bulk_execute.hpp"
		#include "asio/execution/bulk_guarantee.hpp"
		#include "asio/execution/connect.hpp"
		#include "asio/execution/context.hpp"
		#include "asio/execution/context_as.hpp"
		#include "asio/execution/execute.hpp"
		#include "asio/execution/executor.hpp"
		#include "asio/execution/invocable_archetype.hpp"
		#include "asio/execution/mapping.hpp"
		#include "asio/execution/occupancy.hpp"
		#include "asio/execution/operation_state.hpp"
		#include "asio/execution/outstanding_work.hpp"
		#include "asio/execution/prefer_only.hpp"
		#include "asio/execution/receiver.hpp"
		#include "asio/execution/receiver_invocation_error.hpp"
		#include "asio/execution/relationship.hpp"
		#include "asio/execution/schedule.hpp"
		#include "asio/execution/scheduler.hpp"
		#include "asio/execution/sender.hpp"
		#include "asio/execution/set_done.hpp"
		#include "asio/execution/set_error.hpp"
		#include "asio/execution/set_value.hpp"
		#include "asio/execution/start.hpp"
		#include "asio/execution_context.hpp"
		#include "asio/executor.hpp"
		#include "asio/executor_work_guard.hpp"
		#include "asio/generic/basic_endpoint.hpp"
		#include "asio/generic/datagram_protocol.hpp"
		#include "asio/generic/raw_protocol.hpp"
		#include "asio/generic/seq_packet_protocol.hpp"
		#include "asio/generic/stream_protocol.hpp"
		#include "asio/handler_alloc_hook.hpp"
		#include "asio/handler_continuation_hook.hpp"
		#include "asio/handler_invoke_hook.hpp"
		#include "asio/high_resolution_timer.hpp"
		#include "asio/io_context.hpp"
		#include "asio/io_context_strand.hpp"
		#include "asio/io_service.hpp"
		#include "asio/io_service_strand.hpp"
		#include "asio/ip/address.hpp"
		#include "asio/ip/address_v4.hpp"
		#include "asio/ip/address_v4_iterator.hpp"
		#include "asio/ip/address_v4_range.hpp"
		#include "asio/ip/address_v6.hpp"
		#include "asio/ip/address_v6_iterator.hpp"
		#include "asio/ip/address_v6_range.hpp"
		#include "asio/ip/network_v4.hpp"
		#include "asio/ip/network_v6.hpp"
		#include "asio/ip/bad_address_cast.hpp"
		#include "asio/ip/basic_endpoint.hpp"
		#include "asio/ip/basic_resolver.hpp"
		#include "asio/ip/basic_resolver_entry.hpp"
		#include "asio/ip/basic_resolver_iterator.hpp"
		#include "asio/ip/basic_resolver_query.hpp"
		#include "asio/ip/host_name.hpp"
		#include "asio/ip/icmp.hpp"
		#include "asio/ip/multicast.hpp"
		#include "asio/ip/resolver_base.hpp"
		#include "asio/ip/resolver_query_base.hpp"
		#include "asio/ip/tcp.hpp"
		#include "asio/ip/udp.hpp"
		#include "asio/ip/unicast.hpp"
		#include "asio/ip/v6_only.hpp"
		#include "asio/is_applicable_property.hpp"
		#include "asio/is_executor.hpp"
		#include "asio/is_read_buffered.hpp"
		#include "asio/is_write_buffered.hpp"
		#include "asio/local/basic_endpoint.hpp"
		#include "asio/local/connect_pair.hpp"
		#include "asio/local/datagram_protocol.hpp"
		#include "asio/local/stream_protocol.hpp"
		#include "asio/multiple_exceptions.hpp"
		#include "asio/packaged_task.hpp"
		#include "asio/placeholders.hpp"
		#include "asio/posix/basic_descriptor.hpp"
		#include "asio/posix/basic_stream_descriptor.hpp"
		#include "asio/posix/descriptor.hpp"
		#include "asio/posix/descriptor_base.hpp"
		#include "asio/posix/stream_descriptor.hpp"
		#include "asio/post.hpp"
		#include "asio/prefer.hpp"
		#include "asio/query.hpp"
		#include "asio/read.hpp"
		#include "asio/read_at.hpp"
		#include "asio/read_until.hpp"
		#include "asio/redirect_error.hpp"
		#include "asio/require.hpp"
		#include "asio/require_concept.hpp"
		#include "asio/serial_port.hpp"
		#include "asio/serial_port_base.hpp"
		#include "asio/signal_set.hpp"
		#include "asio/socket_base.hpp"
		#include "asio/static_thread_pool.hpp"
		#include "asio/steady_timer.hpp"
		#include "asio/strand.hpp"
		#include "asio/streambuf.hpp"
		#include "asio/system_context.hpp"
		#include "asio/system_error.hpp"
		#include "asio/system_executor.hpp"
		#include "asio/system_timer.hpp"
		#include "asio/this_coro.hpp"
		#include "asio/thread.hpp"
		#include "asio/thread_pool.hpp"
		#include "asio/time_traits.hpp"
		#include "asio/use_awaitable.hpp"
		#include "asio/use_future.hpp"
		#include "asio/uses_executor.hpp"
		#include "asio/version.hpp"
		#include "asio/wait_traits.hpp"
		#include "asio/windows/basic_object_handle.hpp"
		#include "asio/windows/basic_overlapped_handle.hpp"
		#include "asio/windows/basic_random_access_handle.hpp"
		#include "asio/windows/basic_stream_handle.hpp"
		#include "asio/windows/object_handle.hpp"
		#include "asio/windows/overlapped_handle.hpp"
		#include "asio/windows/overlapped_ptr.hpp"
		#include "asio/windows/random_access_handle.hpp"
		#include "asio/windows/stream_handle.hpp"
		#include "asio/write.hpp"
		#include "asio/write_at.hpp"
	#endif
	#if defined(ASIO2_USE_SSL)
		#include <asio/ssl.hpp>
	#endif
#else
	#include <boost/asio.hpp>
	#if defined(ASIO2_USE_SSL)
		#include <boost/asio/ssl.hpp>
	#endif
	#ifndef ASIO_VERSION
		#define ASIO_VERSION BOOST_ASIO_VERSION
	#endif

	#ifndef ASIO_CONST_BUFFER
		#define ASIO_CONST_BUFFER BOOST_ASIO_CONST_BUFFER
	#endif
	#ifndef ASIO_MUTABLE_BUFFER
		#define ASIO_MUTABLE_BUFFER BOOST_ASIO_MUTABLE_BUFFER
	#endif
	#ifndef ASIO_NOEXCEPT
		#define ASIO_NOEXCEPT BOOST_ASIO_NOEXCEPT
	#endif
	#ifndef ASIO_CORO_REENTER
		#define ASIO_CORO_REENTER BOOST_ASIO_CORO_REENTER
	#endif
	#ifndef ASIO_CORO_YIELD
		#define ASIO_CORO_YIELD BOOST_ASIO_CORO_YIELD
	#endif
	#ifndef ASIO_CORO_FORK
		#define ASIO_CORO_FORK BOOST_ASIO_CORO_FORK
	#endif
	#ifndef ASIO_INITFN_AUTO_RESULT_TYPE
		#define ASIO_INITFN_AUTO_RESULT_TYPE BOOST_ASIO_INITFN_AUTO_RESULT_TYPE
	#endif
	#ifndef ASIO_COMPLETION_TOKEN_FOR
		#define ASIO_COMPLETION_TOKEN_FOR BOOST_ASIO_COMPLETION_TOKEN_FOR
	#endif
	#ifndef ASIO_NO_TS_EXECUTORS
		#ifdef BOOST_ASIO_NO_TS_EXECUTORS
			#define ASIO_NO_TS_EXECUTORS BOOST_ASIO_NO_TS_EXECUTORS
		#endif
	#endif
	#ifndef ASIO_HANDLER_LOCATION
		#define ASIO_HANDLER_LOCATION BOOST_ASIO_HANDLER_LOCATION
	#endif
	#ifndef ASIO_ENABLE_BUFFER_DEBUGGING
		#ifdef BOOST_ASIO_ENABLE_BUFFER_DEBUGGING
			#define ASIO_ENABLE_BUFFER_DEBUGGING BOOST_ASIO_ENABLE_BUFFER_DEBUGGING
		#endif
	#endif
	#ifndef ASIO_MOVE_ARG
		#define ASIO_MOVE_ARG BOOST_ASIO_MOVE_ARG
	#endif
	#ifndef ASIO_MOVE_CAST
		#define ASIO_MOVE_CAST BOOST_ASIO_MOVE_CAST
	#endif
	#ifndef ASIO_HANDLER_TYPE
		#define ASIO_HANDLER_TYPE BOOST_ASIO_HANDLER_TYPE
	#endif
#endif // ASIO_STANDALONE

#ifdef ASIO_STANDALONE
	namespace asio
	{
		using error_condition = std::error_condition;
	}
#else
	namespace boost::asio
	{
		using error_code      = ::boost::system::error_code;
		using system_error    = ::boost::system::system_error;
		using error_condition = ::boost::system::error_condition;
		using error_category  = ::boost::system::error_category;
	}
	namespace asio = ::boost::asio;
	namespace bho  = ::boost; // bho means boost header only

	// [ adding definitions to namespace alias ]
	// This is currently not allowed and probably won't be in C++1Z either,
	// but note that a recent proposal is allowing
	// https://stackoverflow.com/questions/31629101/adding-definitions-to-namespace-alias?r=SearchResults
	//namespace asio
	//{
	//	using error_code   = ::boost::system::error_code;
	//	using system_error = ::boost::system::system_error;
	//}
#endif // ASIO_STANDALONE

namespace asio2
{
	using error_code      = ::asio::error_code;
	using system_error    = ::asio::system_error;
	using error_condition = ::asio::error_condition;
	using error_category  = ::asio::error_category;
}

#ifdef ASIO_STANDALONE
namespace asio
#else
namespace boost::asio
#endif
{
	/*
	 * used for rdc mode, call("abc") or async_call("abc")
	 * Without the following overload, the compilation will fail.
	 */

	template<class CharT, class Traits = std::char_traits<CharT>>
	inline typename std::enable_if_t<
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char    > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, wchar_t > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char16_t> ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char32_t>,
		ASIO_CONST_BUFFER> buffer(CharT* & data) ASIO_NOEXCEPT
	{
		return asio::buffer(std::basic_string_view<CharT>(data));
	}

	template<class CharT, class Traits = std::char_traits<CharT>>
	inline typename std::enable_if_t<
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char    > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, wchar_t > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char16_t> ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char32_t>,
		ASIO_CONST_BUFFER> buffer(const CharT* & data) ASIO_NOEXCEPT
	{
		return asio::buffer(std::basic_string_view<CharT>(data));
	}

	template<class CharT, class Traits = std::char_traits<CharT>>
	inline typename std::enable_if_t<
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char    > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, wchar_t > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char16_t> ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char32_t>,
		ASIO_CONST_BUFFER> buffer(CharT* const& data) ASIO_NOEXCEPT
	{
		return asio::buffer(std::basic_string_view<CharT>(data));
	}

	template<class CharT, class Traits = std::char_traits<CharT>>
	inline typename std::enable_if_t<
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char    > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, wchar_t > ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char16_t> ||
		std::is_same_v<std::remove_cv_t<std::remove_reference_t<CharT>>, char32_t>,
		ASIO_CONST_BUFFER> buffer(const CharT* const& data) ASIO_NOEXCEPT
	{
		return asio::buffer(std::basic_string_view<CharT>(data));
	}
}

#include <asio2/base/detail/pop_options.hpp>

#endif // !__ASIO2_ASIO_HPP__
