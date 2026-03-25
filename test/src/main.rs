fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod test {

    use openmls::prelude::*;

    #[tokio::test]
    async fn test() {
        MlsGroup::new(todo!(), todo!(), todo!(), todo!())
            .await
            .unwrap();
    }
}
