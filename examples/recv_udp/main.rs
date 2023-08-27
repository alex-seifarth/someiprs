// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2023 Alexander Seifarth
//
// This file is part of `someip-rsmw`.
// `someip-rsmw` is free software: you can redistribute it and/or modify it under the terms
// of the GNU General Public License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// `someip-rsmw` is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Foobar.
// If not, see <https://www.gnu.org/licenses/>.

use someiprs::endpoint;

#[tokio::main]
async fn main() {
    let token = tokio_util::sync::CancellationToken::new();
    let mut task_handles : Vec<tokio::task::JoinHandle<()>> = vec![];
    let addrs = tokio::net::lookup_host("127.0.0.1:8089").await
        .expect("Cannot resolve address");
    for addr in addrs {
        println!("Create UDP tasks for {:?}", addr);
        // task_handles.push(
        //     tokio::spawn(
        //         endpoint::start_udp_endpoint(addr, token.clone())
        //     )
        // );
    }
    println!("{} tasks started.", task_handles.len());

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
    }
    token.cancel();
    for handle in task_handles.into_iter() {
        let _ = handle.await;
    }
}