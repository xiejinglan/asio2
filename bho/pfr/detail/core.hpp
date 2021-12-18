// Copyright (c) 2016-2021 Antony Polukhin
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BHO_PFR_DETAIL_CORE_HPP
#define BHO_PFR_DETAIL_CORE_HPP
#pragma once

#include <bho/pfr/detail/config.hpp>

// Each core provides `bho::pfr::detail::tie_as_tuple` and
// `bho::pfr::detail::for_each_field_dispatcher` functions.
//
// The whole PFR library is build on top of those two functions.
#if BHO_PFR_USE_CPP17
#   include <bho/pfr/detail/core17.hpp>
#elif BHO_PFR_USE_LOOPHOLE
#   include <bho/pfr/detail/core14_loophole.hpp>
#else
#   include <bho/pfr/detail/core14_classic.hpp>
#endif

#endif // BHO_PFR_DETAIL_CORE_HPP
