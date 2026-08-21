use tarantool::space::Space;
use tarantool::tuple::{FunctionArgs, FunctionCtx, Tuple};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct CustomPayload {
    user_id: u32,
    points: u32,
}

// we are exporting a function for Tarantool here.
#[no_mangle]
pub extern "C" fn add_some_action(ctx: FunctionCtx, args: FunctionArgs) -> i32 {

    // extracting arguments passed from Lua
    let payload: CustomPayload = match args.into() {
        Ok(p) => p,
        Err(_) => return -1,
    };

    // we locate the "users" space (table) directly in the process memory
    let mut space = Space::find("users").expect("Space not found");
    
    // get the current row
    let tuple = space.get(&(payload.user_id,)).unwrap().unwrap();
    
    // implementing high-performance business logic...
    // In a real project, there would be fields update, or perhaps something else
    let mut updated_tuple = tuple;

    // return the result back to Lua
    ctx.return_tuple(&updated_tuple).unwrap()
}
