use tarantool::net_box::Conn;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct UserRow {
    id: u32,
    username: String,
    bucket_id: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connecting to Tarantool (default port: 3301)
    let conn = Conn::new(("127.0.0.1", 3301), None).map_err(|e| e.to_string())?;
    
    // awaiting connection readiness
    conn.wait_connected(None).map_err(|e| e.to_string())?;
    println!("successfully connected to Tarantool !");

    // any data for insertion
    let new_user = UserRow {
        id: 101,
        username: "rust_developer".to_string(),
        bucket_id: 1,
    };

    // Calling a stored Lua function for insertion
    // In high-load systems commonly used the call the API via `call`
    let result: Vec<UserRow> = conn.call("box.space.users:insert", &vec![new_user], None)
        .map_err(|e| e.to_string())?
        .unwrap();

    println!("data successfully saved: {:?}", result);

    // retrieving data (via select) by primary key
    let user_id: u32 = 101;
    let select_result: Vec<UserRow> = conn.call("box.space.users:get", &(user_id,), None)
        .map_err(|e| e.to_string())?
        .unwrap();

    println!("retrieved data: {:?}", select_result);

    Ok(())

}
