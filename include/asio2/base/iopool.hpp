/*
 * COPYRIGHT (C) 2017-2021, zhllxt
 *
 * author   : zhllxt
 * email    : 37792738@qq.com
 * 
 * Distributed under the GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
 * (See accompanying file LICENSE or see <http://www.gnu.org/licenses/>)
 */

#ifndef __ASIO2_IOPOOL_HPP__
#define __ASIO2_IOPOOL_HPP__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
#pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <type_traits>
#include <memory>
#include <algorithm>
#include <atomic>
#include <unordered_set>
#include <map>
#include <functional>

#include <asio2/base/error.hpp>
#include <asio2/base/define.hpp>
#include <asio2/base/detail/util.hpp>

namespace asio2::detail
{
	// unbelievable :
	// the 1 sfinae need use   std::declval<std::decay_t<T>>()
	// the 2 sfinae need use  (std::declval<std::decay_t<T>>())
	// the 3 sfinae need use ((std::declval<std::decay_t<T>>()))

	//-----------------------------------------------------------------------------------

	template<class T, class R = void>
	struct is_io_context_pointer : std::false_type {};

	template<class T>
	struct is_io_context_pointer<T, std::void_t<decltype(
		std::declval<std::decay_t<T>>()->~io_context()), void>> : std::true_type {};

	template<class T, class R = void>
	struct is_io_context_object : std::false_type {};

	template<class T>
	struct is_io_context_object<T, std::void_t<decltype(
		std::declval<std::decay_t<T>>().~io_context()), void>> : std::true_type {};

	//-----------------------------------------------------------------------------------

	template<class T, class R = void>
	struct is_executor_work_guard_pointer : std::false_type {};

	template<class T>
	struct is_executor_work_guard_pointer<T, std::void_t<decltype(
		(std::declval<std::decay_t<T>>())->~executor_work_guard()), void>> : std::true_type {};

	template<class T, class R = void>
	struct is_executor_work_guard_object : std::false_type {};

	template<class T>
	struct is_executor_work_guard_object<T, std::void_t<decltype(
		(std::declval<std::decay_t<T>>()).~executor_work_guard()), void>> : std::true_type {};

	//-----------------------------------------------------------------------------------

	static_assert(is_io_context_pointer<asio::io_context*  >::value);
	static_assert(is_io_context_pointer<asio::io_context*& >::value);
	static_assert(is_io_context_pointer<asio::io_context*&&>::value);
	static_assert(is_io_context_pointer<std::shared_ptr<asio::io_context>  >::value);
	static_assert(is_io_context_pointer<std::shared_ptr<asio::io_context>& >::value);
	static_assert(is_io_context_pointer<std::shared_ptr<asio::io_context>&&>::value);
	static_assert(is_io_context_pointer<std::shared_ptr<asio::io_context>const&>::value);
	static_assert(is_io_context_object<asio::io_context  >::value);
	static_assert(is_io_context_object<asio::io_context& >::value);
	static_assert(is_io_context_object<asio::io_context&&>::value);

	//-----------------------------------------------------------------------------------

	class iopool;

	class io_t
	{
		friend class iopool;
	public:
		io_t(asio::io_context* ioc, std::atomic<std::size_t>& pending) noexcept
			: context_(ioc)
			, pending_(pending)
		{
		}
		~io_t() noexcept
		{
		}

		inline asio::io_context                        & context() noexcept { return (*(this->context_)); }
		inline std::atomic<std::size_t>                & pending() noexcept { return    this->pending_  ; }
		inline std::unordered_set<asio::steady_timer*> & timers () noexcept { return    this->timers_   ; }

		template<class Object>
		inline void regobj(Object* p)
		{
			if (p)
			{
				asio::dispatch(this->context(), [this, p, optr = p->derived().selfptr()]() mutable
				{
					std::size_t k = reinterpret_cast<std::size_t>(p);
					this->objects_[k] = [p, optr = std::move(optr)]() mutable
					{
						detail::ignore_unused(optr);
						p->stop();
					};
				});
			}
		}

		template<class Object>
		inline void unregobj(Object* p)
		{
			if (p)
			{
				// must use post, beacuse the "for each objects_" was called in the iopool.stop,
				// then the object->stop is called in the for each, then the unregobj is called 
				// in the object->stop, if we erase the elem of the objects_ directly at here,
				// it will cause the iterator is invalid when executed at "for each objects_" .
				asio::post(this->context(), [this, p, optr = p->derived().selfptr()]() mutable
				{
					detail::ignore_unused(optr);
					this->objects_.erase(reinterpret_cast<std::size_t>(p));
				});
			}
		}

		/**
		 * @brief
		 */
		inline void cancel()
		{
			// moust read write the timers_ in io_context thread by "post"
			// when code run to here, the io_context maybe stopped already.
			asio::post(this->context(), [this]() mutable
			{
				for (asio::steady_timer* timer : this->timers_)
				{
					// when the timer is canceled, it will erase itself from timers_.
					try
					{
						timer->cancel();
					}
					catch (system_error const&)
					{
					}
				}

				for (auto&[ptr, fun] : this->objects_)
				{
					detail::ignore_unused(ptr);
					if (fun)
					{
						fun();
					}
				}

				this->timers_.clear();
				this->objects_.clear();
			});
		}

		/**
		 * @brief initialize the thread id to "std::this_thread::get_id()"
		 */
		inline void init_thread_id() noexcept
		{
			this->thread_id_ = std::this_thread::get_id();
		}

		/**
		 * @brief uninitialize the thread id to empty.
		 */
		inline void fini_thread_id() noexcept
		{
			this->thread_id_ = std::thread::id{};
		}

		/**
		 * @brief return the thread id of the current io_context running in.
		 */
		inline std::thread::id get_thread_id() const noexcept
		{
			return this->thread_id_;
		}

		/**
		 * @brief Determine whether the current io_context is running in the current thread.
		 */
		inline bool running_in_this_thread() const noexcept
		{
			return (std::this_thread::get_id() == this->thread_id_);
		}

	protected:
		// Do not use shared_ptr<io_context>, it will cause a lot of problems. If the user
		// calls asio::post([ptr = shared_ptr<io_context>(context)](){}) after io_context is 
		// stopped, it will cause io_context can't be destructed, because io_context's destructor
		// will clear it's task queue which generated by asio::post, but because the queue
		// saved the shared_ptr<io_context> of itself, then circular reference is occured,
		// when use io_context for steady_timer, it maybe create a thread, and the circular
		// reference will cause the thread can not quit, and finally the thread will be
		// more and more, then cause the program crash.
		asio::io_context                       * context_ = nullptr;

		// the strand will cause some problem when used in dll.
		// 1. when declare a strand in dll, and export it, when use the strand in exe which 
		//    exported by the dll, the strand.running_in_this_thread will false, even if it
		//    is called in the io_context thread.
		// 2. when declare a strand in dll, and export it, when use asio::bind_executor(strand
		//    in exe, it will cause deak lock.
		//    eg: async_connect(endpoint, asio::bind_executor(strand, callback)); the callback
		//        will never be called.
		//asio::io_context::strand                 strand_;

		// Use this variable to ensure async_send function was executed correctly.
		// see : send_cp.hpp "# issue x:"
		std::atomic<std::size_t>               & pending_;

		// Use this variable to save the timers that have not been closed properly.
		// If we don't do this, the following problem will occurs:
		// user call client.stop, when the code is run to before the iopool's 
		// wait_for_io_context_stopped, and user call client.start_timer at another
		// thread, this will cause the wait_for_io_context_stopped will block forever 
		// until the timer expires.
		// e.g:
		//     {
		//         asio2::timer timer;
		//         timer.post([&]()
		//         {
		//             timer.start_timer(1, std::chrono::seconds(1), []() {});
		//         });
		//     } // the timer's destructor will be called here.
		// when the timer's destructor is called, it will call the "stop_all_timers"
		// function, the "stop_all_timers" will "post a event", this "post a event"
		// will executed before the "timer.start_timer(1,...)", so when the 
		// "timer.start_timer(1,...)" is executed, nobody has a chance to cancel it,
		// and this will cause the iopool's wait_for_io_context_stopped function
		// blocked forever.
		std::unordered_set<asio::steady_timer*>      timers_;

		// Used to save the server or client or other objects, when iopool.stop is called,
		// the objects.stop will be called automaticly.
		std::map<std::size_t, std::function<void()>> objects_;

		// the thread id of the current io_context running in.
		std::thread::id                              thread_id_{};
	};

	//-----------------------------------------------------------------------------------

	template<class T, class R = void>
	struct is_io_t_pointer : std::false_type {};

	template<class T>
	struct is_io_t_pointer<T, std::void_t<decltype(
		((std::declval<std::decay_t<T>>()))->~io_t()), void>> : std::true_type {};

	template<class T, class R = void>
	struct is_io_t_object : std::false_type {};

	template<class T>
	struct is_io_t_object<T, std::void_t<decltype(
		((std::declval<std::decay_t<T>>())).~io_t()), void>> : std::true_type {};

	//-----------------------------------------------------------------------------------

	/**
	 * io_context pool
	 */
	class iopool
	{
	public:
		/**
		 * @brief constructor
		 * @param concurrency - the pool size, default is double the number of CPU cores
		 */
		explicit iopool(std::size_t concurrency = default_concurrency())
		{
			if (concurrency == 0)
			{
				concurrency = default_concurrency();
			}

			for (std::size_t i = 0; i < concurrency; ++i)
			{
				this->iocs_.emplace_back(std::make_unique<asio::io_context>(1));
			}

			for (std::size_t i = 0; i < concurrency; ++i)
			{
				this->iots_.emplace_back(std::make_unique<io_t>(this->iocs_[i].get(), this->pending_));
			}

			this->threads_.reserve(this->iots_.size());
			this->guards_ .reserve(this->iots_.size());
		}

		/**
		 * @brief destructor
		 */
		~iopool()
		{
			this->stop();
		}

		/**
		 * @brief run all io_context objects in the pool.
		 */
		bool start()
		{
			clear_last_error();

			std::lock_guard<std::mutex> guard(this->mutex_);

			if (!this->stopped_)
			{
				set_last_error(asio::error::already_started);
				return true;
			}

			if (!this->guards_.empty() || !this->threads_.empty())
			{
				set_last_error(asio::error::already_started);
				return true;
			}

			std::vector<std::promise<void>> promises(this->iots_.size());

			// Create a pool of threads to run all of the io_contexts. 
			for (std::size_t i = 0; i < this->iots_.size(); ++i)
			{
				auto& iot = this->iots_[i];
				std::promise<void>& promise = promises[i];

				/// Restart the io_context in preparation for a subsequent run() invocation.
				/**
				 * This function must be called prior to any second or later set of
				 * invocations of the run(), run_one(), poll() or poll_one() functions when a
				 * previous invocation of these functions returned due to the io_context
				 * being stopped or running out of work. After a call to restart(), the
				 * io_context object's stopped() function will return @c false.
				 *
				 * This function must not be called while there are any unfinished calls to
				 * the run(), run_one(), poll() or poll_one() functions.
				 */
				iot->context().restart();

				this->guards_.emplace_back(iot->context().get_executor());

				// start work thread
				this->threads_.emplace_back([&iot, &promise]() mutable
				{
					iot->thread_id_ = std::this_thread::get_id();

					// after the thread id is seted already, we set the promise
					promise.set_value();

					// should we catch the exception ? 
					// If an exception occurs here, what should we do ?
					// We should handle exceptions in other business functions to ensure that
					// exceptions will not be triggered here.
					//try
					//{
						iot->context().run();
					//}
					//catch (system_error const& e)
					//{
					//	std::ignore = e;

					//	ASIO2_ASSERT(false);
					//}

					// memory leaks occur when SSL is used in multithreading
					// https://github.com/chriskohlhoff/asio/issues/368
				#if defined(ASIO2_USE_SSL)
					OPENSSL_thread_stop();
				#endif
				});
			}

			for (std::size_t i = 0; i < this->iots_.size(); ++i)
			{
				promises[i].get_future().wait();
			}

		#if defined(_DEBUG) || defined(DEBUG)
			for (std::size_t i = 0; i < this->iots_.size(); ++i)
			{
				ASIO2_ASSERT(this->iots_[i]->get_thread_id() == this->threads_[i].get_id());
			}
		#endif

			this->stopped_ = false;

			return true;
		}

		/**
		 * @brief stop all io_context objects in the pool
		 * blocking until all posted event has completed already.
		 * After we call iog.reset(), when an asio::post(io_context,...) execution ends, the count
		 * of the io_context will be checked. If the count equals 0, the io_context will be closed. Then 
		 * the subsequent call of asio:: post(io_context,...) will fail, and the post event will not
		 * be executed. When our program exits, it will nest call asio:: post (io_context...) to post
		 * many events, so when an asio::post(io_context,...) inside someone asio::post(io_context,...)
		 * has not yet been executed, the io_context may have been closed, which will result in the
		 * nested asio::post(io_context,...) never being executed.
		 */
		void stop()
		{
			{
				std::lock_guard<std::mutex> guard(this->mutex_);

				if (this->stopped_)
					return;

				if (this->guards_.empty() && this->threads_.empty())
					return;

				if (this->running_in_threads())
					return this->cancel();

				this->stopped_ = true;
			}

			// Waiting for all nested events to complete.
			// The mutex_ must be released while waiting, otherwise, the stop function may be called
			// in the communication thread and the lock will be requested, which is already held here,
			// so leading to deadlock.
			this->wait_for_io_context_stopped();

			{
				std::lock_guard<std::mutex> guard(this->mutex_);

				// call executor_work_guard reset,and then the io_context working thread will be exited.
				// In fact, the guards has called reset already, but there is no problem with repeated calls
				for (auto & iog : this->guards_)
				{
					ASIO2_ASSERT(iog.owns_work() == false);
					iog.reset();
				}

				// Wait for all threads to exit. 
				for (auto & thread : this->threads_)
				{
					thread.join();
				}

				this->guards_ .clear();
				this->threads_.clear();

			#if defined(_DEBUG) || defined(DEBUG)
				for (std::size_t i = 0; i < this->iots_.size(); ++i)
				{
					ASIO2_ASSERT(this->iots_[i]->objects_.empty());
				}
			#endif
			}
		}

		/**
		 * @brief check whether the io_context pool is stopped
		 */
		inline bool stopped() const noexcept
		{
			return (this->stopped_);
		}

		/**
		 * @brief get an io_t to use
		 */
		inline io_t& get(std::size_t index = static_cast<std::size_t>(-1)) noexcept
		{
			ASIO2_ASSERT(!this->iots_.empty());

			return *(this->iots_[this->next(index)]);
		}

		/**
		 * @brief get an io_context to use
		 */
		inline asio::io_context& get_context(std::size_t index = static_cast<std::size_t>(-1)) noexcept
		{
			ASIO2_ASSERT(!this->iots_.empty());

			return this->iots_[this->next(index)]->context();
		}

		/**
		 * @brief Determine whether current code is running in the io_context pool threads.
		 */
		inline bool running_in_threads() const noexcept
		{
			std::thread::id curr_tid = std::this_thread::get_id();
			for (auto & thread : this->threads_)
			{
				if (curr_tid == thread.get_id())
					return true;
			}
			return false;
		}

		/**
		 * @brief Determine whether current code is running in the io_context thread by index
		 */
		inline bool running_in_thread(std::size_t index) const noexcept
		{
			ASIO2_ASSERT(index < this->threads_.size());

			if (!(index < this->threads_.size()))
				return false;

			return (std::this_thread::get_id() == this->threads_[index].get_id());
		}

		/**
		 * @brief get io_context pool size.
		 */
		inline std::size_t size() const noexcept
		{
			return this->iots_.size();
		}

		/**
		 * @brief 
		 */
		inline std::atomic<std::size_t>& pending() noexcept
		{
			return this->pending_;
		}

		/**
		 * Use to ensure that all nested asio::post(...) events are fully invoked.
		 */
		inline void wait_for_io_context_stopped()
		{
			{
				std::lock_guard<std::mutex> guard(this->mutex_);

				if (this->running_in_threads())
					return this->cancel();

				// wiat fo all pending events completed.
				while (this->pending_ > std::size_t(0))
					std::this_thread::sleep_for(std::chrono::milliseconds(0));

				// first reset the acceptor io_context work guard
				if (!this->guards_.empty())
					this->guards_.front().reset();
			}

			constexpr auto max = std::chrono::milliseconds(10);
			constexpr auto min = std::chrono::milliseconds(1);

			// second wait indefinitely until the acceptor io_context is stopped
			for (std::size_t i = 0; i < std::size_t(1) && i < this->iocs_.size(); ++i)
			{
				auto t1 = std::chrono::steady_clock::now();
				auto& ioc = this->iocs_[i];
				auto& iot = this->iots_[i];
				while (!ioc->stopped())
				{
					// the timer may not be canceled successed when using visual
					// studio break point for debugging, so cancel it at each loop
					iot->cancel();

					auto t2 = std::chrono::steady_clock::now();
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
					std::this_thread::sleep_for(std::clamp(ms, min, max));
				}
				iot->thread_id_ = std::thread::id{};
				ASIO2_ASSERT(iot->timers().empty());
				ASIO2_ASSERT(iot->objects_.empty());
			}

			{
				std::lock_guard<std::mutex> guard(this->mutex_);

				for (std::size_t i = 1; i < this->guards_.size(); ++i)
				{
					this->guards_[i].reset();
				}
			}

			for (std::size_t i = 1; i < this->iocs_.size(); ++i)
			{
				auto t1 = std::chrono::steady_clock::now();
				auto& ioc = this->iocs_[i];
				auto& iot = this->iots_[i];
				while (!ioc->stopped())
				{
					// the timer may not be canceled successed when using visual
					// studio break point for debugging, so cancel it at each loop
					iot->cancel();

					auto t2 = std::chrono::steady_clock::now();
					auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1);
					std::this_thread::sleep_for(std::clamp(ms, min, max));
				}
				iot->thread_id_ = std::thread::id{};
				ASIO2_ASSERT(iot->timers().empty());
				ASIO2_ASSERT(iot->objects_.empty());
			}
		}

		/**
		 * 
		 */
		inline void cancel()
		{
			for (std::size_t i = 0; i < this->iocs_.size(); ++i)
			{
				auto& ioc = this->iocs_[i];
				auto& iot = this->iots_[i];
				if (!ioc->stopped())
				{
					iot->cancel();
				}
			}
		}

		/**
		 * @brief
		 */
		inline std::size_t next(std::size_t index) noexcept
		{
			// Use a round-robin scheme to choose the next io_context to use. 
			return (index < this->size() ? index : ((++(this->next_)) % this->size()));
		}

	protected:
		/// threads to run all of the io_context
		std::vector<std::thread>                                     threads_;

		/// The pool of io_context. 
		std::vector<std::unique_ptr<asio::io_context>>               iocs_;

		/// The pool of io_context. 
		std::vector<std::unique_ptr<io_t>>                           iots_;

		/// 
		std::mutex                                                   mutex_;

		/// Flag whether the io_context pool has stopped already
		bool                                                         stopped_  = true;

		/// The next io_context to use for a connection. 
		std::size_t                                                  next_     = 0;

		// Give all the io_contexts executor_work_guard to do so that their run() functions will not 
		// exit until they are explicitly stopped. 
		std::vector<asio::executor_work_guard<asio::io_context::executor_type>> guards_;

		// 
		std::atomic<std::size_t>                                     pending_  = 0;
	};

	class iopool_base
	{
	public:
		iopool_base() = default;
		virtual ~iopool_base() {}

		virtual bool                        start  ()                           = 0;
		virtual void                        stop   ()                           = 0;
		virtual bool                        stopped()            const noexcept = 0;
		virtual io_t                      & get    (std::size_t index) noexcept = 0;
		virtual std::size_t                 size   ()            const noexcept = 0;
		virtual std::atomic<std::size_t>  & pending()                  noexcept = 0;
		virtual bool             running_in_threads()            const noexcept = 0;
	};

	class default_iopool : public iopool_base
	{
	public:
		explicit default_iopool(std::size_t concurrency) : impl_(concurrency)
		{
		}

		/**
		 * @brief destructor
		 */
		virtual ~default_iopool()
		{
			this->impl_.stop();
		}

		/**
		 * @brief run all io_context objects in the pool.
		 */
		virtual bool start() override
		{
			return this->impl_.start();
		}

		/**
		 * @brief stop all io_context objects in the pool
		 */
		virtual void stop() override
		{
			this->impl_.stop();
		}

		/**
		 * @brief check whether the io_context pool is stopped
		 */
		virtual bool stopped() const noexcept override
		{
			return this->impl_.stopped();
		}

		/**
		 * @brief get an io_t to use
		 */
		virtual io_t& get(std::size_t index) noexcept override
		{
			return this->impl_.get(index);
		}

		/**
		 * @brief get io_context pool size.
		 */
		virtual std::size_t size() const noexcept override
		{
			return this->impl_.size();
		}

		/**
		 * @brief 
		 */
		virtual std::atomic<std::size_t>& pending() noexcept override
		{
			return this->impl_.pending();
		}

		/**
		 * @brief Determine whether current code is running in the io_context pool threads.
		 */
		virtual bool running_in_threads() const noexcept override
		{
			return this->impl_.running_in_threads();
		}

	protected:
		iopool impl_;
	};

	/**
	 * This io_context pool is passed in by the user
	 */
	template<class Container>
	class user_iopool : public iopool_base
	{
	public:
		using copy_container_type = typename detail::remove_cvref_t<Container>;
		using copy_value_type     = typename copy_container_type::value_type;

		using io_container_type = std::conditional_t<
			is_io_context_pointer<copy_value_type>::value,
			std::vector<std::unique_ptr<io_t>>, std::vector<io_t*>>;
		using io_value_type     = typename io_container_type::value_type;

		/**
		 * @brief constructor
		 */
		template<class C>
		explicit user_iopool(C&& copy) : copy_(std::forward<C>(copy))
		{
			// std::shared_ptr<io_context> , io_context*
			if constexpr (is_io_context_pointer<copy_value_type>::value)
			{
				// why use std::addressof(*ioc) ?
				// the io_context pointer maybe "std::shared_ptr<io_context> , io_context*"
				for (auto& ioc : copy_)
				{
					iots_.emplace_back(std::make_unique<io_t>(std::addressof(*ioc), this->pending_));
				}
			}
			// std::shared_ptr<io_t> , io_t*
			else
			{
				for (auto& iot : copy_)
				{
					iots_.emplace_back(std::addressof(*iot));
				}
			}
		}

		/**
		 * @brief destructor
		 */
		virtual ~user_iopool()
		{
			this->stop();
		}

		/**
		 * @brief run all io_context objects in the pool.
		 */
		virtual bool start() override
		{
			clear_last_error();

			std::lock_guard<std::mutex> guard(this->mutex_);

			if (!this->stopped_)
			{
				set_last_error(asio::error::already_started);
				return true;
			}

			this->stopped_ = false;

			return true;
		}

		/**
		 * @brief stop all io_context objects in the pool
		 */
		virtual void stop() override
		{
			std::lock_guard<std::mutex> guard(this->mutex_);

			if (this->stopped_)
				return;

			// wiat fo all pending events completed.
			while (this->pending_ > std::size_t(0))
				std::this_thread::sleep_for(std::chrono::milliseconds(0));

			this->stopped_ = true;
		}

		/**
		 * @brief check whether the io_context pool is stopped
		 */
		virtual bool stopped() const noexcept override
		{
			return (this->stopped_);
		}

		/**
		 * @brief get an io_t to use
		 */
		virtual io_t& get(std::size_t index) noexcept override
		{
			return *(this->iots_[this->next(index)]);
		}

		/**
		 * @brief get io_context pool size.
		 */
		virtual std::size_t size() const noexcept override
		{
			return this->iots_.size();
		}

		/**
		 * @brief
		 */
		virtual std::atomic<std::size_t>& pending() noexcept override
		{
			return this->pending_;
		}

		/**
		 * @brief
		 */
		inline std::size_t next(std::size_t index) noexcept
		{
			// Use a round-robin scheme to choose the next io_context to use. 
			return (index < this->size() ? index : ((++(this->next_)) % this->size()));
		}

		/**
		 * @brief Determine whether current code is running in the io_context pool threads.
		 */
		virtual bool running_in_threads() const noexcept override
		{
			std::thread::id curr_tid = std::this_thread::get_id();
			for (auto& iot : this->iots_)
			{
				if (curr_tid == iot->get_thread_id())
					return true;
			}
			return false;
		}

	protected:
		/// user container copy, maybe the user passed shared_ptr, and expect us to keep it
		copy_container_type                      copy_;

		/// The pool of io_t. 
		io_container_type                        iots_;

		/// 
		std::mutex                               mutex_;

		/// Flag whether the io_context pool has stopped already
		bool                                     stopped_  = true;

		/// The next io_context to use for a connection. 
		std::size_t                              next_     = 0;

		/// 
		std::atomic<std::size_t>                 pending_  = 0;
	};

	template<class derived_t, class args_t = void>
	class iopool_cp
	{
	public:
		template<class T>
		explicit iopool_cp(T&& v)
		{
			using type = typename detail::remove_cvref_t<T>;

			if /**/ constexpr (std::is_integral_v<type>)
			{
				using pool_type = default_iopool;
				this->iopool_ = std::make_unique<pool_type>(v);
			}
			else if constexpr (is_io_context_pointer<type>::value)
			{
				ASIO2_ASSERT(v && "The io_context pointer is nullptr.");

				using container = std::vector<type>;
				container copy{ std::forward<T>(v) };

				using pool_type = user_iopool<container>;
				this->iopool_ = std::make_unique<pool_type>(std::move(copy));
			}
			else if constexpr (is_io_context_object<type>::value)
			{
				static_assert(std::is_reference_v<std::remove_cv_t<T>>);

				using container = std::vector<std::add_pointer_t<type>>;
				container copy{ &v };

				using pool_type = user_iopool<container>;
				this->iopool_ = std::make_unique<pool_type>(std::move(copy));
			}
			else if constexpr (is_io_t_pointer<type>::value)
			{
				ASIO2_ASSERT(v && "The io_t pointer is nullptr.");

				using container = std::vector<type>;
				container copy{ std::forward<T>(v) };

				using pool_type = user_iopool<container>;
				this->iopool_ = std::make_unique<pool_type>(std::move(copy));
			}
			else if constexpr (is_io_t_object<type>::value)
			{
				static_assert(std::is_reference_v<std::remove_cv_t<T>>);

				using container = std::vector<std::add_pointer_t<type>>;
				container copy{ &v };

				using pool_type = user_iopool<container>;
				this->iopool_ = std::make_unique<pool_type>(std::move(copy));
			}
			else
			{
				ASIO2_ASSERT(!v.empty() && "The container is empty.");

				using pool_type = user_iopool<type>;
				this->iopool_ = std::make_unique<pool_type>(std::forward<T>(v));
			}

			for (std::size_t i = 0, size = iopool_->size(); i < size; ++i)
			{
				iots_.emplace_back(std::addressof(iopool_->get(i)));
			}
		}

		~iopool_cp() = default;

		/**
		 * The wait_stop() function blocks until the stop() function has been called.
		 */
		void wait_stop()
		{
			if (this->iopool().running_in_threads())
			{
				set_last_error(asio::error::operation_not_supported);
				return;
			}

			try
			{
				clear_last_error();

				derived_t& derive = static_cast<derived_t&>(*this);

				std::promise<error_code> promise;
				std::future<error_code> future = promise.get_future();

				// We must use asio::post to ensure the wait_stop_timer_ is read write in the 
				// same thread.
				asio::post(iots_[0]->context(), [this, this_ptr = derive.selfptr(), promise = std::move(promise)]
				() mutable
				{
					try
					{
						this->wait_stop_timer_ = std::make_unique<asio::steady_timer>(iots_[0]->context());

						this->iots_[0]->timers().emplace(this->wait_stop_timer_.get());

						this->wait_stop_timer_->expires_after((std::chrono::nanoseconds::max)());
						this->wait_stop_timer_->async_wait(
						[this_ptr = std::move(this_ptr), promise = std::move(promise)]
						(const error_code&) mutable
						{
							detail::ignore_unused(this_ptr);

							promise.set_value(error_code{});
						});
					}
					catch (system_error const& e)
					{
						promise.set_value(e.code());
					}
				});

				set_last_error(future.get());
			}
			catch (system_error const& e)
			{
				set_last_error(e);
			}
		}

		/**
		 * The wait_for() function blocks until all work has finished and 
		 * until the specified duration has elapsed.
		 *
		 * @param rel_time - The duration for which the call may block.
		 */
		template <typename Rep, typename Period>
		void wait_for(const std::chrono::duration<Rep, Period>& rel_time)
		{
			if (this->iopool().running_in_threads())
			{
				set_last_error(asio::error::operation_not_supported);
				return;
			}

			try
			{
				clear_last_error();
				asio::steady_timer timer(iots_[0]->context());
				timer.expires_after(rel_time);
				timer.wait();
			}
			catch (system_error const& e)
			{
				set_last_error(e);
			}
		}

		/**
		 * The wait_until() function blocks until all work has finished and 
		 * until the specified time has been reached.
		 *
		 * @param abs_time - The time point until which the call may block.
		 */
		template <typename Clock, typename Duration>
		void wait_until(const std::chrono::time_point<Clock, Duration>& abs_time)
		{
			if (this->iopool().running_in_threads())
			{
				set_last_error(asio::error::operation_not_supported);
				return;
			}

			try
			{
				clear_last_error();
				asio::steady_timer timer(iots_[0]->context());
				timer.expires_at(abs_time);
				timer.wait();
			}
			catch (system_error const& e)
			{
				set_last_error(e);
			}
		}

		/**
		 * The wait_signal() function blocks util some signal delivered.
		 * 
		 * @return The delivered signal number. Maybe invalid value when some exception occured.
		 */
		template <class... Ints>
		int wait_signal(Ints... signal_number)
		{
			if (this->iopool().running_in_threads())
			{
				set_last_error(asio::error::operation_not_supported);
				return -1;
			}

			try
			{
				clear_last_error();

				// note: The variable name signals will conflict with the macro signals of qt
				asio::signal_set signalset(iots_[0]->context());

				(signalset.add(signal_number), ...);

				std::promise<int> promise;
				std::future<int> future = promise.get_future();

				signalset.async_wait([&](const error_code& /*ec*/, int signo)
				{
					promise.set_value(signo);
				});

				return future.get();
			}
			catch (system_error const& e)
			{
				set_last_error(e);
			}

			return -2;
		}

		/**
		 * Get the iopool_base interface reference.
		 */
		inline iopool_base& iopool() noexcept { return (*(this->iopool_)); }

	protected:
		inline io_t& _get_io(std::size_t index = static_cast<std::size_t>(-1)) noexcept
		{
			ASIO2_ASSERT(!iots_.empty());
			std::size_t n = index < iots_.size() ? index : ((++next_) % iots_.size());
			return *(iots_[n]);
		}

		inline bool is_iopool_stopped() const noexcept
		{
			return this->iopool_->stopped();
		}

		inline bool start_iopool()
		{
			return this->iopool_->start();
		}

		inline void stop_iopool()
		{
			if (this->is_iopool_stopped())
				return;

			derived_t& derive = static_cast<derived_t&>(*this);

			// if the server's or client's iopool is user_iopool, and when the server.stop 
			// or client.stop is called, we need notify the timer to cancel for the function
			// wait_stop, otherwise the wait_stop function will blocked forever.
			// We must use asio::post to ensure the wait_stop_timer_ is read write in the 
			// same thread.
			asio::post(iots_[0]->context(), [this, this_ptr = derive.selfptr()]() mutable
			{
				detail::ignore_unused(this_ptr);
				try
				{
					if (this->wait_stop_timer_)
					{
						this->iots_[0]->timers().erase(this->wait_stop_timer_.get());
						this->wait_stop_timer_->cancel();
					}
				}
				catch (system_error const&)
				{
				}
			});

			this->iopool_->stop();
		}

	protected:
		/// the io_context pool for socket event
		std::unique_ptr<iopool_base>             iopool_;

		/// Use a copy to avoid calling the virtual function "iopool_base::get"
		std::vector<io_t*>                       iots_;

		/// The next io_context to use for a connection. 
		std::size_t                              next_ = 0;

		/// the timer used for wait_stop function.
		std::unique_ptr<asio::steady_timer>      wait_stop_timer_;
	};
}

namespace asio2
{
	using io_t   = detail::io_t;
	using iopool = detail::iopool;
}

#endif // !__ASIO2_IOPOOL_HPP__
