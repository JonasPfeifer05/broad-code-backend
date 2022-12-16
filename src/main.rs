#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket;

use std::convert::Infallible;
use std::env;
use diesel::{Connection, Insertable, PgConnection, Queryable, QueryDsl, RunQueryDsl};
use rocket::{Build, Request, request, Response, Rocket};
use rocket::serde::json::Json;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::serde::{Deserialize, Serialize};
use rocket_sync_db_pools::database;
use crate::broad_code_user::{name, password};
use dotenvy::dotenv;
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, decode, DecodingKey, encode, EncodingKey, Validation};
use rocket::http::{Header, HeaderMap, Status};
use jsonwebtoken::Header as HeaderToken;
use chrono::{
    Utc, Duration
};
use rocket::request::{FromRequest, Outcome};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[options("/<_..>")]
fn all_options() {}

#[database("my_db")]
pub struct Db(diesel::PgConnection);

diesel::table! {
    broad_code_user (id) {
        id -> Int4,
        name -> Varchar,
        password -> Varchar,
    }
}

diesel::table! {
    broad_code_session_token (id) {
        id -> Int4,
        token -> Varchar,
    }
}

#[derive(Serialize, Deserialize, Queryable, Debug, Insertable)]
#[table_name = "broad_code_user"]
pub struct User {
    id: i32,
    name: String,
    password: String,
}

#[derive(Serialize,Deserialize)]
pub struct UserData {
    name: String,
    password: String,
}

#[derive(Insertable)]
#[table_name = "broad_code_user"]
pub struct NewUser {
    name: String,
    password: String,
}

#[derive(Serialize, Deserialize, Queryable, Debug, Insertable)]
#[table_name = "broad_code_session_token"]
pub struct Token {
    id: i32,
    token: String,
}

#[derive(Serialize,Deserialize)]
pub struct TokenData {
    token: String,
}

#[derive(Insertable)]
#[table_name = "broad_code_session_token"]
pub struct NewToken {
    token: String,
}

#[post("/get_user", format = "json", data="<user_data>")]
fn get_user(user_data: Json<UserData>) -> Json<UserData> {
    use crate::broad_code_user::dsl::broad_code_user;

    let connection = &mut establish_connection();
    let results = broad_code_user
        .filter(name.eq(&user_data.name).and(password.eq(&user_data.password)))
        .limit(1)
        .load::<User>(connection)
        .expect("Error loading posts");

    Json(UserData {name: results.get(0).unwrap().name.clone(), password: results.get(0).unwrap().password.clone()} )
}

#[post("/add_user", format = "json", data="<user_data>")]
fn add_user(user_data: Json<UserData>) -> Json<User> {
    let connection = &mut establish_connection();
    Json(create_user(connection, user_data.into_inner()))
}

#[post("/remove_user", format = "json", data="<user_data>")]
fn remove_user(user_data: Json<UserData>) -> Json<bool> {
    use crate::broad_code_user::dsl::broad_code_user;

    let connection = &mut establish_connection();
    diesel::delete(broad_code_user.filter(name.eq(&user_data.name).and(password.eq(&user_data.password))))
        .execute(connection)
        .expect("failed to delete");

    Json(true)
}

#[post("/generate_jwt", format="json", data="<user_data>")]
pub fn generate_jwt(user_data: Json<UserData>) -> Json<JWTData> {
    let connection = &mut establish_connection();

    Json(JWTData{token: create_jwt(connection, user_data.into_inner())})
}

pub struct RequestHeaders<'h>(&'h HeaderMap<'h>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestHeaders<'r> {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let request_headers = request.headers();
        Outcome::Success(RequestHeaders(request_headers))
    }
}

#[derive(Serialize, Deserialize)]
pub struct JWTData {
    token: String,
}

#[post("/header")]
pub fn header(headers: RequestHeaders) -> Json<JWTData> {
    let token = headers.0.get_one("Authorization").unwrap();
    Json(JWTData {token: token.to_string()})
}

#[post("/validate_jwt")]
pub fn validate_jwt(headers: RequestHeaders) -> Json<bool> {
    use crate::broad_code_user::dsl::broad_code_user;

    let token = headers.0.get_one("Authorization").unwrap();

    let claims = decode_jwt(token.to_string());
    let user = UserData { name: claims.name, password: claims.password };

    if claims.exp < Utc::now().timestamp() as usize {
        println!("");
        return Json(false);
    }

    let connection = &mut establish_connection();
    let results = broad_code_user
        .filter(name.eq(&user.name).and(password.eq(&user.password)))
        .limit(1)
        .load::<User>(connection)
        .expect("Error loading posts");

    return Json(results.len() == 1);
}

#[launch]
fn rocket() -> Rocket<Build> {
    let rocket = rocket::build();

    rocket
        .attach(Db::fairing())
        .attach(CORS)
        .mount("/", routes![get_user, header, add_user, all_options, generate_jwt, validate_jwt, remove_user])
}

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn create_user(conn: &mut PgConnection, data: UserData) -> User {
    let new_user = NewUser {name: data.name, password: data.password};

    diesel::insert_into(broad_code_user::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Error saving new post")
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    name: String,
    password: String,
    exp: usize,
}

static PRIVATE_KEY: &str = "To_change";

pub fn create_jwt(conn: &mut PgConnection, data: UserData) -> String {
    let exp = (Utc::now() + Duration::days(1)).timestamp() as usize;
    let claims = Claims { name: data.name, password: data.password, exp };
    let jwt = encode(&HeaderToken::default(), &claims,  &EncodingKey::from_secret(PRIVATE_KEY.as_bytes()));

    jwt.unwrap()
}

pub fn decode_jwt(jwt: String) -> Claims {
    let result = decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(PRIVATE_KEY.as_bytes()),
        &Validation::new(Algorithm::HS256)
    );

    result.unwrap().claims
}
