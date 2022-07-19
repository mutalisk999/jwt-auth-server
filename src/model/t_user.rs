use rbatis::crud::CRUD;
use rbatis::crud_table;

use crate::utils::g::RB_SESSION;

#[crud_table]
#[derive(Default, Clone, Debug)]
pub struct TUser {
    pub id: Option<u64>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub role: Option<u8>,
}


pub async fn query_t_user_by_name(username: &String) -> Result<Option<TUser>, rbatis::core::Error> {
    let session = RB_SESSION.as_ref().read().await;
    let w = session
        .as_ref()
        .unwrap()
        .new_wrapper()
        .eq("username", username);

    session
        .as_ref()
        .unwrap()
        .fetch_by_wrapper(w)
        .await
}