// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Frame System benchmarks.

use alloc::vec;
use frame_benchmarking::v2::*;
use frame_support::{dispatch::DispatchClass, traits::Get};
use frame_system::{Call, Pallet as System, RawOrigin};
use sp_runtime::traits::Hash;

pub struct Pallet<T: Config>(System<T>);
// The `Config` hooks `prepare_set_code_data`, `setup_set_code_requirements` and
// `verify_set_code` went with the `set_code` benchmark: this fork has no
// dispatchable that can write `:code`. What is left to benchmark is `remark`
// and `remark_with_event`, which is the whole call surface of the pallet.
pub trait Config: frame_system::Config {}

#[benchmarks]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn remark(
		b: Linear<0, { *T::BlockLength::get().max.get(DispatchClass::Normal) as u32 }>,
	) -> Result<(), BenchmarkError> {
		let remark_message = vec![1; b as usize];
		let caller = whitelisted_caller();

		#[extrinsic_call]
		remark(RawOrigin::Signed(caller), remark_message);

		Ok(())
	}

	#[benchmark]
	fn remark_with_event(
		b: Linear<0, { *T::BlockLength::get().max.get(DispatchClass::Normal) as u32 }>,
	) -> Result<(), BenchmarkError> {
		let remark_message = vec![1; b as usize];
		let caller: T::AccountId = whitelisted_caller();
		let hash = T::Hashing::hash(&remark_message[..]);

		#[extrinsic_call]
		remark_with_event(RawOrigin::Signed(caller.clone()), remark_message);

		System::<T>::assert_last_event(
			frame_system::Event::<T>::Remarked { sender: caller, hash }.into(),
		);
		Ok(())
	}

	impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
}
