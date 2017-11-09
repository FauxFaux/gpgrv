error_chain!{
    foreign_links {
        Base64(::base64::DecodeError);
        Io(::std::io::Error);
    }
}
