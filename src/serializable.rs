pub trait Serializable {
	fn serialize(&self) -> Vec<u8>;
}

pub enum Error {
	DecodeError
}

pub trait Deserializable {
	type Error;

	fn deserialize(buf: &[u8]) -> Result<Self, Self::Error> where Self: Sized;
}