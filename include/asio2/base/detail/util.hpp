/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_UTIL_HPP__
#define __ASIO2_UTIL_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <climits>
#include <cctype>

#include <string>
#include <string_view>
#include <type_traits>
#include <memory>
#include <future>
#include <functional>
#include <tuple>
#include <utility>
#include <atomic>
#include <limits>
#include <thread>
#include <mutex>
#include <shared_mutex>

// when compiled with "Visual Studio 2017 - Windows XP (v141_xp)"
// there is hasn't shared_mutex
#ifndef ASIO2_HAS_SHARED_MUTEX
	#if defined(_MSC_VER)
		#if _HAS_SHARED_MUTEX
			#define ASIO2_HAS_SHARED_MUTEX 1
			#define asio2_shared_mutex std::shared_mutex
			#define asio2_shared_lock  std::shared_lock
			#define asio2_unique_lock  std::unique_lock
		#else
			#define ASIO2_HAS_SHARED_MUTEX 0
			#define asio2_shared_mutex std::mutex
			#define asio2_shared_lock  std::lock_guard
			#define asio2_unique_lock  std::lock_guard
		#endif
	#else
			#define ASIO2_HAS_SHARED_MUTEX 1
			#define asio2_shared_mutex std::shared_mutex
			#define asio2_shared_lock  std::shared_lock
			#define asio2_unique_lock  std::unique_lock
	#endif
#endif

#include <asio2/base/error.hpp>

namespace asio2::detail
{
	enum class state_t : std::int8_t { stopped, stopping, starting, started };

	static long constexpr  tcp_handshake_timeout = 5 * 1000;
	static long constexpr  udp_handshake_timeout = 5 * 1000;
	static long constexpr http_handshake_timeout = 5 * 1000;

	static long constexpr  tcp_connect_timeout   = 5 * 1000;
	static long constexpr  udp_connect_timeout   = 5 * 1000;
	static long constexpr http_connect_timeout   = 5 * 1000;

	static long constexpr  tcp_silence_timeout   = 60 * 60 * 1000;
	static long constexpr  udp_silence_timeout   = 60 * 1000;
	static long constexpr http_silence_timeout   = 85 * 1000;
	static long constexpr mqtt_silence_timeout   = 90 * 1000; // 60 * 1.5

	static long constexpr http_execute_timeout   = 5 * 1000;
	static long constexpr icmp_execute_timeout   = 4 * 1000;

	static long constexpr ssl_shutdown_timeout   = 5 * 1000;
	static long constexpr  ws_shutdown_timeout   = 5 * 1000;

	static long constexpr ssl_handshake_timeout  = 5 * 1000;
	static long constexpr  ws_handshake_timeout  = 5 * 1000;

	/*
	 * The read buffer has to be at least as large
	 * as the largest possible control frame including
	 * the frame header.
	 * refrenced from beast stream.hpp
	 */
	// udp MTU : https://zhuanlan.zhihu.com/p/301276548
	static std::size_t constexpr  tcp_frame_size = 1536;
	static std::size_t constexpr  udp_frame_size = 1024;
	static std::size_t constexpr http_frame_size = 1536;

	static std::size_t constexpr max_buffer_size = (std::numeric_limits<std::size_t>::max)();

	// std::thread::hardware_concurrency() is not constexpr, so use it with function form
	template<typename = void>
	inline std::size_t default_concurrency() noexcept { return std::thread::hardware_concurrency() * 2; }
}

namespace asio2::detail
{
	template <typename Enumeration>
	inline constexpr auto to_underlying(Enumeration const value) noexcept ->
		typename std::underlying_type<Enumeration>::type
	{
		return static_cast<typename std::underlying_type<Enumeration>::type>(value);
	}

	/**
	 * BKDR Hash Function
	 */
	template<typename = void>
	inline std::size_t bkdr_hash(const unsigned char * const p, std::size_t size) noexcept
	{
		std::size_t v = 0;
		for (std::size_t i = 0; i < size; ++i)
		{
			v = v * 131 + static_cast<std::size_t>(p[i]);
		}
		return v;
	}

	/**
	 * Fnv1a Hash Function
	 * Reference from Visual c++ implementation, see vc++ std::hash
	 */
	template<typename T>
	inline T fnv1a_hash(const unsigned char * const p, const T size) noexcept
	{
		static_assert(sizeof(T) == 4 || sizeof(T) == 8, "Must be 32 or 64 digits");
		T v;
		if constexpr (sizeof(T) == 4)
			v = 2166136261u;
		else
			v = 14695981039346656037ull;
		for (T i = 0; i < size; ++i)
		{
			v ^= static_cast<T>(p[i]);
			if constexpr (sizeof(T) == 4)
				v *= 16777619u;
			else
				v *= 1099511628211ull;
		}
		return (v);
	}

	template<typename T>
	inline T fnv1a_hash(T v, const unsigned char * const p, const T size) noexcept
	{
		static_assert(sizeof(T) == 4 || sizeof(T) == 8, "Must be 32 or 64 digits");
		for (T i = 0; i < size; ++i)
		{
			v ^= static_cast<T>(p[i]);
			if constexpr (sizeof(T) == 4)
				v *= 16777619u;
			else
				v *= 1099511628211ull;
		}
		return (v);
	}


	template <typename... Ts>
	inline constexpr void ignore_unused(Ts const& ...) noexcept {}

	template <typename... Ts>
	inline constexpr void ignore_unused() noexcept {}


	template<class T>
	class copyable_wrapper
	{
	public:
		using value_type = T;

		template<typename ...Args>
		copyable_wrapper(Args&&... args) noexcept : raw(std::forward<Args>(args)...) { }
		template<typename = void>
		copyable_wrapper(T&& o) noexcept : raw(std::move(o)) { }

		copyable_wrapper(copyable_wrapper&&) noexcept = default;
		copyable_wrapper& operator=(copyable_wrapper&&) noexcept = default;

		copyable_wrapper(copyable_wrapper const& r) noexcept : raw(const_cast<T&&>(r.raw)) { }
		copyable_wrapper& operator=(copyable_wrapper const& r) noexcept { raw = const_cast<T&&>(r.raw); }

		T& operator()() noexcept { return raw; }

	protected:
		T raw;
	};

	template<typename, typename = void>
	struct is_copyable_wrapper : std::false_type {};

	template<typename T>
	struct is_copyable_wrapper<T, std::void_t<typename T::value_type,
		typename std::enable_if_t<std::is_same_v<T,
		copyable_wrapper<typename T::value_type>>>>> : std::true_type {};

	template<class T>
	inline constexpr bool is_copyable_wrapper_v = is_copyable_wrapper<T>::value;


	template<class Rep, class Period, class Fn>
	std::shared_ptr<asio::steady_timer> mktimer(asio::io_context& ioc,
		std::chrono::duration<Rep, Period> duration, Fn&& fn)
	{
		std::shared_ptr<asio::steady_timer> timer = std::make_shared<asio::steady_timer>(ioc);
		auto post = std::make_shared<std::unique_ptr<std::function<void()>>>();
		*post = std::make_unique<std::function<void()>>(
		[duration, f = std::forward<Fn>(fn), timer, post]() mutable
		{
			timer->expires_after(duration);
			timer->async_wait([&f, &post](const error_code& ec) mutable
			{
				if (f(ec))
					(**post)();
				else
					(*post).reset();
			});
		});
		(**post)();
		return timer;
	}

	struct safe_timer
	{
		explicit safe_timer(asio::io_context& ioc) : timer(ioc)
		{
			canceled.clear();
		}

		inline void cancel()
		{
			try
			{
				this->canceled.test_and_set();
				this->timer.cancel();
			}
			catch (system_error const&)
			{
			}
		}

		/// Timer impl
		asio::steady_timer timer;

		/// Why use this flag, beacuase the ec param maybe zero when the timer callback is
		/// called after the timer cancel function has called already.
		/// Before : need reset the "canceled" flag to false, otherwise after "client.stop();"
		/// then call client.start(...) again, this reconnect timer will doesn't work .
		/// can't put this "clear" code into the timer handle function, beacuse the stop timer
		/// maybe called many times. so, when the "canceled" flag is set false in the timer handle
		/// and the stop timer is called later, then the "canceled" flag will be set true again .
		std::atomic_flag   canceled;
	};

	template<class T, bool isIntegral = true, bool isUnsigned = true, bool SkipZero = true>
	class id_maker
	{
	public:
		id_maker(T init = static_cast<T>(1)) noexcept : id(init)
		{
			if constexpr (isIntegral)
			{
				static_assert(std::is_integral_v<T>, "T must be integral");
				if constexpr (isUnsigned)
				{
					static_assert(std::is_unsigned_v<T>, "T must be unsigned integral");
				}
				else
				{
					static_assert(true);
				}
			}
			else
			{
				static_assert(true);
			}
		}
		inline T mkid() noexcept
		{
			if constexpr (SkipZero)
			{
				T r = id.fetch_add(static_cast<T>(1));
				return (r == 0 ? id.fetch_add(static_cast<T>(1)) : r);
			}
			else
			{
				return id.fetch_add(static_cast<T>(1));
			}
		}
	protected:
		std::atomic<T> id;
	};


	template<class T>
	struct remove_cvref
	{
		typedef std::remove_cv_t<std::remove_reference_t<T>> type;
	};

	template< class T >
	using remove_cvref_t = typename remove_cvref<T>::type;

	// https://stackoverflow.com/questions/53945490/how-to-assert-that-a-constexpr-if-else-clause-never-happen
	// https://en.cppreference.com/w/cpp/utility/variant/visit
	// https://en.cppreference.com/w/cpp/language/if#Constexpr_If
	template<class...> inline constexpr bool always_false_v = false;


	template <typename Tup, typename Fun, std::size_t... I>
	inline void for_each_tuple_impl(Tup&& t, Fun&& f, std::index_sequence<I...>)
	{
		(f(std::get<I>(std::forward<Tup>(t))), ...);
	}

	template <typename Tup, typename Fun>
	inline void for_each_tuple(Tup&& t, Fun&& f)
	{
		for_each_tuple_impl(std::forward<Tup>(t), std::forward<Fun>(f), std::make_index_sequence<
			std::tuple_size_v<detail::remove_cvref_t<Tup>>>{});
	}


	// example : static_assert(is_template_instantiable_v<std::vector, double>);
	//           static_assert(is_template_instantiable_v<std::optional, int, int>);
	template<template<typename...> typename T, typename AlwaysVoid, typename... Args>
	struct is_template_instantiable : std::false_type {};

	template<template<typename...> typename T, typename... Args>
	struct is_template_instantiable<T, std::void_t<T<Args...>>, Args...> : std::true_type {};

	template<template<typename...> typename T, typename... Args>
	inline constexpr bool is_template_instantiable_v = is_template_instantiable<T, void, Args...>::value;


	// example : static_assert(is_template_instance_of<std::vector, std::vector<int>>);
	template<template<typename...> class U, typename T>
	struct is_template_instance_of : std::false_type {};

	template<template<typename...> class U, typename...Args>
	struct is_template_instance_of<U, U<Args...>> : std::true_type {};

	template<template<typename...> class U, typename...Args>
	inline constexpr bool is_template_instance_of_v = is_template_instance_of<U, Args...>::value;

	template<typename T> struct is_tuple : is_template_instance_of<std::tuple, T> {};


	template<typename, typename = void>
	struct is_string : std::false_type {};

	template<typename T>
	struct is_string<T, std::void_t<typename T::value_type, typename T::traits_type, typename T::allocator_type,
		typename std::enable_if_t<std::is_same_v<T,
		std::basic_string<typename T::value_type, typename T::traits_type, typename T::allocator_type>>>>>
		: std::true_type {};

	template<class T>
	inline constexpr bool is_string_v = is_string<detail::remove_cvref_t<T>>::value;


	template<typename, typename = void>
	struct is_string_view : std::false_type {};

	template<typename T>
	struct is_string_view<T, std::void_t<typename T::value_type, typename T::traits_type,
		typename std::enable_if_t<std::is_same_v<T,
		std::basic_string_view<typename T::value_type, typename T::traits_type>>>>> : std::true_type {};

	template<class T>
	inline constexpr bool is_string_view_v = is_string_view<detail::remove_cvref_t<T>>::value;


	template<typename, typename = void>
	struct is_char_pointer : std::false_type {};

	// char const * 
	// detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>
	// char
	template<typename T>
	struct is_char_pointer<T, std::void_t<typename std::enable_if_t<
		 std::is_pointer_v<                                             detail::remove_cvref_t<T>>  &&
		!std::is_pointer_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>> &&
		(
			std::is_same_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>, char    > ||
			std::is_same_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>, wchar_t > ||
		#if defined(__cpp_lib_char8_t)
			std::is_same_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>, char8_t > ||
		#endif
			std::is_same_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>, char16_t> ||
			std::is_same_v<detail::remove_cvref_t<std::remove_pointer_t<detail::remove_cvref_t<T>>>, char32_t>
		)
		>>> : std::true_type {};

	template<class T>
	inline constexpr bool is_char_pointer_v = is_char_pointer<detail::remove_cvref_t<T>>::value;


	template<typename, typename = void>
	struct is_char_array : std::false_type {};

	template<typename T>
	struct is_char_array<T, std::void_t<typename std::enable_if_t <
		std::is_array_v<detail::remove_cvref_t<T>>  &&
		(
			std::is_same_v<detail::remove_cvref_t<std::remove_all_extents_t<detail::remove_cvref_t<T>>>, char    > ||
			std::is_same_v<detail::remove_cvref_t<std::remove_all_extents_t<detail::remove_cvref_t<T>>>, wchar_t > ||
		#if defined(__cpp_lib_char8_t)
			std::is_same_v<detail::remove_cvref_t<std::remove_all_extents_t<detail::remove_cvref_t<T>>>, char8_t > ||
		#endif
			std::is_same_v<detail::remove_cvref_t<std::remove_all_extents_t<detail::remove_cvref_t<T>>>, char16_t> ||
			std::is_same_v<detail::remove_cvref_t<std::remove_all_extents_t<detail::remove_cvref_t<T>>>, char32_t>
		)
		>>> : std::true_type {};

	template<class T>
	inline constexpr bool is_char_array_v = is_char_array<detail::remove_cvref_t<T>>::value;


	template<class T>
	inline constexpr bool is_character_string_v =
		is_string_v      <T> ||
		is_string_view_v <T> ||
		is_char_pointer_v<T> ||
		is_char_array_v  <T>;


	template<class, class, class = void>
	struct has_stream_operator : std::false_type {};

	template<class T, class D>
	struct has_stream_operator<T, D, std::void_t<decltype(T{} << D{})>> : std::true_type{};

	template<class, class, class = void>
	struct has_equal_operator : std::false_type {};

	template<class T, class D>
	struct has_equal_operator<T, D, std::void_t<decltype(T{} = D{})>> : std::true_type{};


	template<class, class = void>
	struct can_convert_to_string : std::false_type {};

	template<class T>
	struct can_convert_to_string<T, std::void_t<decltype(
		std::string(std::declval<T>()).size(),
		std::declval<std::string>() = std::declval<T>()
		)>> : std::true_type{};

	template<class T>
	inline constexpr bool can_convert_to_string_v = can_convert_to_string<detail::remove_cvref_t<T>>::value;


	template<typename T>
	inline std::string to_string(T&& v)
	{
		using type = detail::remove_cvref_t<T>;

		std::string s;

		if constexpr (is_string_view_v<type>)
		{
			s = { v.data(),v.size() };
		}
		else if constexpr (std::is_integral_v<type>)
		{
			s = std::to_string(v);
		}
		else if constexpr (std::is_pointer_v<type>)
		{
			if (v) s = v;
		}
		else if constexpr (std::is_array_v<type>)
		{
			s = std::forward<T>(v);
		}
		else
		{
			s = std::forward<T>(v);
		}
		return s;
	}

	template<typename T>
	inline std::string_view to_string_view(const T& v)
	{
		using type = detail::remove_cvref_t<T>;

		if constexpr (is_string_view_v<type>)
		{
			return std::string_view{ v };
		}
		else if constexpr (std::is_pointer_v<type>)
		{
			return (v ? std::string_view{ v } : std::string_view{});
		}
		else if constexpr (std::is_array_v<type>)
		{
			return std::string_view{ v };
		}
		else
		{
			return std::string_view{ v };
		}
	}

	template<typename Iterator>
	inline std::string_view to_string_view(const Iterator& first, const Iterator& last)
	{
		using iter_type = typename detail::remove_cvref_t<Iterator>;
		using diff_type = typename std::iterator_traits<iter_type>::difference_type;

		diff_type n = std::distance(first, last);

		if (n < static_cast<diff_type>(0))
		{
			ASIO2_ASSERT(false);
			return std::string_view{};
		}

		if (n == static_cast<diff_type>(0))
		{
			return std::string_view{};
		}

		if constexpr (std::is_pointer_v<iter_type>)
		{
			return { first, static_cast<std::string_view::size_type>(n) };
		}
		else
		{
			return { first.operator->(), static_cast<std::string_view::size_type>(n) };
		}
	}

	template<typename IntegerType, typename T>
	inline IntegerType to_integer(T&& v)
	{
		using type = detail::remove_cvref_t<T>;
		if constexpr (std::is_integral_v<type>)
			return static_cast<IntegerType>(v);
		else
			return static_cast<IntegerType>(std::stoull(to_string(std::forward<T>(v))));
	}

	template<typename Protocol, typename String, typename StrOrInt>
	inline Protocol to_endpoint(String&& host, StrOrInt&& port)
	{
		std::string h = to_string(std::forward<String>(host));
		std::string p = to_string(std::forward<StrOrInt>(port));

		asio::io_context ioc;
		// the resolve function is a time-consuming operation
		if /**/ constexpr (std::is_same_v<asio::ip::udp::endpoint, Protocol>)
		{
			asio::ip::udp::resolver resolver(ioc);
			asio::ip::udp::endpoint endpoint = *resolver.resolve(h, p,
				asio::ip::resolver_base::flags::address_configured);
			return endpoint;
		}
		else if constexpr (std::is_same_v<asio::ip::tcp::endpoint, Protocol>)
		{
			asio::ip::tcp::resolver resolver(ioc);
			asio::ip::tcp::endpoint endpoint = *resolver.resolve(h, p,
				asio::ip::resolver_base::flags::address_configured);
			return endpoint;
		}
		else
		{
			static_assert(detail::always_false_v<Protocol>);
		}
	}

	// Returns true if the current machine is little endian
	template<typename = void>
	inline bool is_little_endian() noexcept
	{
		static std::int32_t test = 1;
		return (*reinterpret_cast<std::int8_t*>(std::addressof(test)) == 1);
	}

	/**
	 * Swaps the order of bytes for some chunk of memory
	 * @param data - The data as a uint8_t pointer
	 * @tparam DataSize - The true size of the data
	 */
	template <std::size_t DataSize>
	inline void swap_bytes(std::uint8_t * data) noexcept
	{
		for (std::size_t i = 0, end = DataSize / 2; i < end; ++i)
			std::swap(data[i], data[DataSize - i - 1]);
	}

	template<class T, class Pointer>
	inline void write(Pointer& p, T v) noexcept
	{
		if constexpr (int(sizeof(T)) > 1)
		{
			// MSDN: The htons function converts a u_short from host to TCP/IP network byte order (which is big-endian).
			// ** This mean the network byte order is big-endian **
			if (is_little_endian())
			{
				swap_bytes<sizeof(T)>(reinterpret_cast<std::uint8_t *>(std::addressof(v)));
			}

			std::memcpy((void*)p, (const void*)&v, sizeof(T));
		}
		else
		{
			static_assert(sizeof(T) == std::size_t(1));

			*p = std::decay_t<std::remove_pointer_t<detail::remove_cvref_t<Pointer>>>(v);
		}

		p += sizeof(T);
	}

	template<class T, class Pointer>
	inline T read(Pointer& p) noexcept
	{
		T v{};

		if constexpr (int(sizeof(T)) > 1)
		{
			std::memcpy((void*)&v, (const void*)p, sizeof(T));

			// MSDN: The htons function converts a u_short from host to TCP/IP network byte order (which is big-endian).
			// ** This mean the network byte order is big-endian **
			if (is_little_endian())
			{
				swap_bytes<sizeof(T)>(reinterpret_cast<std::uint8_t *>(std::addressof(v)));
			}
		}
		else
		{
			static_assert(sizeof(T) == std::size_t(1));

			v = T(*p);
		}

		p += sizeof(T);

		return v;
	}

	// C++ SSO : How to programatically find if a std::wstring is allocated with Short String Optimization?
	// https://stackoverflow.com/questions/65736613/c-sso-how-to-programatically-find-if-a-stdwstring-is-allocated-with-short
	template <class T>
	bool is_used_sso(const T& t) noexcept
	{
		using type = typename detail::remove_cvref_t<T>;
		static type st{};
		return t.capacity() == st.capacity();
	}

	template<class T>
	std::size_t sso_buffer_size() noexcept
	{
		using type = typename detail::remove_cvref_t<T>;
		static type st{};
		return st.capacity();
	}

	// Disable std:string's SSO
	// https://stackoverflow.com/questions/34788789/disable-stdstrings-sso
	// std::string str;
	// str.reserve(sizeof(str) + 1);
	template<class String>
	inline void disable_sso(String& str)
	{
		str.reserve(sso_buffer_size<typename detail::remove_cvref_t<String>>() + 1);
	}

	template<class Integer>
	struct integer_add_sub_guard
	{
		 integer_add_sub_guard(Integer& v) noexcept : v_(v) { ++v_; }
		~integer_add_sub_guard()           noexcept         { --v_; }

		Integer& v_;
	};

	// C++17 class template argument deduction guides
	template<class Integer>
	integer_add_sub_guard(Integer&)->integer_add_sub_guard<Integer>;

	template<class T>
	struct shared_ptr_adapter
	{
		using rawt = typename detail::remove_cvref_t<T>;
		using type = std::conditional_t<detail::is_template_instance_of_v<std::shared_ptr, rawt>,
			rawt, std::shared_ptr<rawt>>;
	};

	template<class T>
	typename detail::shared_ptr_adapter<T>::type to_shared_ptr(T&& t)
	{
		using rawt = typename detail::remove_cvref_t<T>;

		if constexpr (detail::is_template_instance_of_v<std::shared_ptr, rawt>)
		{
			return std::forward<T>(t);
		}
		else
		{
			return std::make_shared<rawt>(std::forward<T>(t));
		}
	}

	//// The following code will cause element_type_adapter<int> compilation failure:
	//// the "int" don't has a type of element_type.
	//template<class T>
	//struct element_type_adapter
	//{
	//	using rawt = typename remove_cvref_t<T>;
	//	using type = std::conditional_t<is_template_instance_of_v<std::shared_ptr, rawt>,
	//		typename rawt::element_type, rawt>;
	//};

	template<class T>
	struct element_type_adapter
	{
		using type = typename detail::remove_cvref_t<T>;
	};

	template<class T>
	struct element_type_adapter<std::shared_ptr<T>>
	{
		using type = typename detail::remove_cvref_t<T>;
	};

	template<class T>
	struct element_type_adapter<std::unique_ptr<T>>
	{
		using type = typename detail::remove_cvref_t<T>;
	};

	template<class T>
	struct element_type_adapter<T*>
	{
		using type = typename detail::remove_cvref_t<T>;
	};
}

namespace asio2
{
	enum class net_protocol : std::int8_t
	{
		udp = 1,

		tcp,
		http,
		websocket,

		tcps,
		https,
		websockets,

		ws = websocket,
		wss = websockets
	};

	enum class response_mode : std::int8_t
	{
		automatic = 1,
		manual,
	};

	template <typename Enumeration>
	inline constexpr auto to_underlying(Enumeration const value) noexcept ->
		typename std::underlying_type<Enumeration>::type
	{
		return static_cast<typename std::underlying_type<Enumeration>::type>(value);
	}

	template <typename... Ts>
	inline constexpr void ignore_unused(Ts const& ...) noexcept {}

	template <typename... Ts>
	inline constexpr void ignore_unused() noexcept {}

	template <class KeyT>
	struct hash;

	template <typename InternetProtocol>
	struct hash<asio::ip::basic_endpoint<InternetProtocol>>
	{
		std::size_t operator()(const asio::ip::basic_endpoint<InternetProtocol>& ep) const noexcept
		{
			return std::hash<std::string_view>()(std::string_view{
				reinterpret_cast<std::string_view::const_pointer>(ep.data()), ep.size() });
		}
	};
}

// custom specialization of std::hash can be injected in namespace std
#if !defined(ASIO_HAS_STD_HASH)
namespace std
{
	template <typename InternetProtocol>
	struct hash<asio::ip::basic_endpoint<InternetProtocol>>
	{
		std::size_t operator()(const asio::ip::basic_endpoint<InternetProtocol>& ep) const noexcept
		{
			// see : struct hash<asio::ip::basic_endpoint<InternetProtocol>> in asio/ip/basic_endpoint.hpp
			return std::hash<std::string_view>()(std::string_view{
				reinterpret_cast<std::string_view::const_pointer>(ep.data()), ep.size() });
		}
	};

	//template<> struct hash<asio::ip::udp::endpoint>
	//{
	//	inline std::size_t operator()(asio::ip::udp::endpoint const& s) const noexcept
	//	{
	//		return std::hash<std::string_view>()(std::string_view{
	//			reinterpret_cast<std::string_view::const_pointer>(s.data()), s.size() });
	//		//return asio2::detail::bkdr_hash((const unsigned char *)(s.data()), s.size());
	//	}
	//};

	//template<> struct hash<asio::ip::tcp::endpoint>
	//{
	//	inline std::size_t operator()(asio::ip::tcp::endpoint const& s) const noexcept
	//	{
	//		return std::hash<std::string_view>()(std::string_view{
	//			reinterpret_cast<std::string_view::const_pointer>(s.data()), s.size() });
	//		//return asio2::detail::bkdr_hash((const unsigned char *)(s.data()), s.size());
	//	}
	//};
}
#endif

//namespace std
//{
//	template <typename InternetProtocol>
//	struct hash<asio::ip::basic_endpoint<InternetProtocol>*>
//	{
//		std::size_t operator()(const asio::ip::basic_endpoint<InternetProtocol>* ep) const noexcept
//		{
//			return 1;
//			return std::hash<std::string_view>()(std::string_view{
//				reinterpret_cast<std::string_view::const_pointer>(ep->data()), ep->size() });
//		}
//	};
//	template <typename InternetProtocol>
//	struct equal_to<asio::ip::basic_endpoint<InternetProtocol>*>
//	{
//		std::size_t operator()(
//			const asio::ip::basic_endpoint<InternetProtocol>* ep1,
//			const asio::ip::basic_endpoint<InternetProtocol>* ep2) const noexcept
//		{
//			return *ep1 == *ep2;
//		}
//	};
//}

namespace asio2
{
	namespace detail
	{
		template<class T>
		struct current_object_result_t
		{
			using type = T&;
		};

		template<class T>
		struct current_object_result_t<std::shared_ptr<T>>
		{
			using type = std::weak_ptr<T>&;
		};

		class [[maybe_unused]] external_linkaged_current_object
		{
		public:
			template<class T>
			[[maybe_unused]] static typename current_object_result_t<T>::type get() noexcept
			{
				if constexpr (detail::is_template_instance_of_v<std::shared_ptr, T>)
				{
					thread_local static std::weak_ptr<typename T::element_type> o{};

					return o;
				}
				else
				{
					thread_local static T o{};

					return o;
				}
			}
		};

		namespace internal_linkaged_current_object
		{
			template<class T>
			[[maybe_unused]] static typename current_object_result_t<T>::type get() noexcept
			{
				if constexpr (detail::is_template_instance_of_v<std::shared_ptr, T>)
				{
					thread_local static std::weak_ptr<typename T::element_type> o{};

					return o;
				}
				else
				{
					thread_local static T o{};

					return o;
				}
			}
		}

		template<class T>
		[[maybe_unused]] inline typename current_object_result_t<T>::type get_current_object() noexcept
		{
			return detail::external_linkaged_current_object::get<T>();
		}
	}

	/**
	 * @brief Get the current caller object in the current thread.
	 * @tparam T - If the object is created on the stack such as "asio2::rpc_client client", the T can
	 *             only be asio2::rpc_client& or asio2::rpc_client*
	 *             If the object is created on the heap such as "std::shared_ptr<asio2::rpc_session>", 
	 *             the T can only be std::shared_ptr<asio2::rpc_session>
	 * @return The return type is same as the T.
	 */
	template<class T>
	[[maybe_unused]] inline T get_current_caller() noexcept
	{
		if /**/ constexpr (detail::is_template_instance_of_v<std::shared_ptr, T>)
		{
			return detail::get_current_object<T>().lock();
		}
		else if constexpr (std::is_reference_v<T>)
		{
			return *detail::get_current_object<std::add_pointer_t<typename detail::remove_cvref_t<T>>>();
		}
		else
		{
			return detail::get_current_object<T>();
		}
	}
}

#endif // !__ASIO2_UTIL_HPP__
