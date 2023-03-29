use std::io::Result as IOResult;

fn main() -> IOResult<()> {
	let text_push_protobuf_files = [
		"../protobuf/proto/ciphrtext/Cipher.proto",
		"../protobuf/proto/ciphrtext/Session.proto",
		"../protobuf/proto/common/Storage.proto",
	];
	let text_push_protobuf_includes = [
		"../protobuf/proto/ciphrtext",
		"../protobuf/proto/common",
		"../protobuf/proto/ciphrmail",
	];
	prost_build::compile_protos(&text_push_protobuf_files, &text_push_protobuf_includes)?;

	for dep in text_push_protobuf_files.iter() {
		println!("cargo:rerun-if-changed={}", dep);
	}

	Ok(())
}
