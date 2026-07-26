/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

fn main() {
    // The protobuf source lives outside this crate. Cargo otherwise only
    // watches the crate directory and can reuse stale generated Rust after
    // bundle.proto changes (notably in release/benchmark builds).
    println!("cargo:rerun-if-changed=../../../proto/bundle.proto");

    let file_descriptor_set =
        protox::compile(["../../../proto/bundle.proto"], ["../../../proto"])
            .expect("failed to parse bundle.proto via protox");

    prost_build::Config::new()
        .compile_fds(file_descriptor_set)
        .expect("failed to generate Rust types from bundle.proto");
}
