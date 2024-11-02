use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use tokio_postgres::{NoTls, Client};
use std::sync::Arc;
use tokio::sync::Mutex;
use bcrypt::{hash, verify, DEFAULT_COST};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use dotenv::dotenv;
use rand::Rng;
use jsonwebtoken::{encode, Header, EncodingKey};
use std::time::{SystemTime, UNIX_EPOCH};
use actix_cors::Cors;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
#[derive(Debug, Deserialize, Serialize)]
struct UpdateUser {
    id: i32, // ID pengguna yang akan diupdate
    nama: Option<String>,
    email: Option<String>,
    pekerjaan: Option<String>,
    tanggal_lahir: Option<String>,
    gender: Option<String>,
    umur: Option<i32>,
    goldar: Option<String>,
    provinsi: Option<String>,
    kabupaten: Option<String>,
    kecamatan: Option<String>,
}
#[derive(Deserialize)]
struct VerifyOtp {
    otp: String,
}

#[derive(Deserialize)]
struct PatchUser {
    nama: Option<String>,
    password: Option<String>,
    email: Option<String>,
    pekerjaan: Option<String>,
    tanggal_lahir: Option<String>, 
    gender: Option<String>,
    umur: Option<i32>,
    goldar: Option<String>,
    provinsi: Option<String>,
    kabupaten: Option<String>,
    kecamatan: Option<String>,
}
#[derive(Deserialize)]
struct DeleteUser {
    id: i32,
}
#[derive(Serialize)]
struct User {
    id: i32,
    nama: String,
    password: String,
    email: String,
    pekerjaan: Option<String>,
    tanggal_lahir: Option<String>, 
    gender: Option<String>,
    umur: Option<i32>,
    goldar: Option<String>,
    provinsi: Option<String>,
    kabupaten: Option<String>,
    kecamatan: Option<String>,
}
#[derive(Deserialize)]
struct NewUser {
    nama: String,
    email: String,
    password: String,
    pekerjaan: String,
    tanggal_lahir: String,
    gender: String,
    umur: i32,
    goldar: String,
    provinsi: String,
    kabupaten: String,
    kecamatan: String,
    question: String,  
    answer: String,    
}
#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}
#[derive(Serialize)]
struct LoginResponse {
    id: i32,
    token: String,
    nama: String,
}
#[derive(Deserialize)]
struct ForgotPasswordRequest {
    email: String,
    question: String,
    answer: String,
    password: String,
}
#[derive(Serialize)]
struct Goldar {
    goldar: String,
    count: i64, // Ganti i32 dengan i64
}
#[derive(Serialize)]
struct GenderStats {
    gender: String,
    count: i64, 
}
#[derive(Serialize)]
struct AgeStats {
    umur: String,
    count: i64, 
}
#[derive(Serialize)]
struct JobStats {
    pekerjaan: String,
    count: i64, 
}
async fn get_gender_stats(
    db_client: web::Data<Arc<Mutex<Client>>>,
    query: web::Query<ProvinceQuery>
) -> impl Responder {
    let province = &query.provinsi; // Mengambil parameter provinsi dari query string
    let client = db_client.lock().await;

    let sql = "
        SELECT gender, COUNT(*) AS count
        FROM users
        WHERE provinsi = $1
        GROUP BY gender
    ";

    let result = client.query(sql, &[province]).await;

    match result {
        Ok(rows) => {
            let mut stats = Vec::new();
            for row in rows {
                let gender: String = row.get(0);
                let count: i64 = row.get(1);
                stats.push(GenderStats { gender, count });
            }
            HttpResponse::Ok().json(stats) // Mengembalikan data dalam bentuk JSON
        },
        Err(e) => {
            eprintln!("Gagal mengambil data gender: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
#[derive(Deserialize)]
struct ProvinceQuery {
    provinsi: String,
}
async fn get_chartjob(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let query = "
        SELECT pekerjaan, COUNT(*) AS count
        FROM users
        GROUP BY pekerjaan
    ";

    let result = client.query(query, &[]).await;

    match result {
        Ok(rows) => {
            let mut stats = Vec::new();
            for row in rows {
                let pekerjaan: String = row.get(0);
                let count: i64 = row.get(1);
                stats.push(JobStats { pekerjaan, count });
            }
            HttpResponse::Ok().json(stats)
        },
        Err(e) => {
            eprintln!("Gagal mengambil data pekerjaan: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
async fn get_chartumur(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;
    // Query untuk menghitung jumlah pengguna berdasarkan rentang umur dari kolom 'umur'
    let query = "
        SELECT
            CASE
                WHEN umur BETWEEN 0 AND 9 THEN '0-9'
                WHEN umur BETWEEN 10 AND 19 THEN '10-19'
                WHEN umur BETWEEN 20 AND 29 THEN '20-29'
                WHEN umur BETWEEN 30 AND 39 THEN '30-39'
                WHEN umur BETWEEN 40 AND 49 THEN '40-49'
                WHEN umur BETWEEN 50 AND 59 THEN '50-59'
                WHEN umur BETWEEN 60 AND 69 THEN '60-69'
                ELSE '70+'
            END AS age_range,
            COUNT(*) AS count
        FROM users
        GROUP BY age_range
    ";

    let result = client.query(query, &[]).await;

    match result {
        Ok(rows) => {
            let mut stats = Vec::new();
            for row in rows {
                let umur: String = row.get(0);
                let count: i64 = row.get(1);
                stats.push(AgeStats { umur, count });
            }
            HttpResponse::Ok().json(stats)
        },
        Err(e) => {
            eprintln!("Gagal mengambil data umur: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn get_chartgender(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;
    // Query untuk menghitung jumlah pengguna berdasarkan gender
    let query = "
        SELECT gender, COUNT(*) AS count
        FROM users
        GROUP BY gender
    ";

    let result = client.query(query, &[]).await;

    match result {
        Ok(rows) => {
            let mut stats = Vec::new();
            for row in rows {
                let gender: String = row.get(0);
                let count: i64 = row.get(1);
                stats.push(GenderStats { gender, count });
            }
            HttpResponse::Ok().json(stats)
        },
        Err(e) => {
            eprintln!("Gagal mengambil data gender: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn get_chartgoldar(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;
    // Query untuk menghitung jumlah pengguna berdasarkan golongan darah
    let query = "
        SELECT goldar, COUNT(*) AS count
        FROM users
        GROUP BY goldar
    ";

    let result = client.query(query, &[]).await;

    match result {
        Ok(rows) => {
            let mut stats = Vec::new();
            for row in rows {
                let goldar: String = row.get(0);
                let count: i64 = row.get(1); // Ganti i32 dengan i64
                stats.push(Goldar { goldar, count });
            }
            HttpResponse::Ok().json(stats)
        },
        Err(e) => {
            eprintln!("Gagal mengambil data golongan darah: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn forgot_password(
    data: web::Json<ForgotPasswordRequest>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let query = "SELECT id, email, question, answer FROM users WHERE email = $1";
    let result = client.query_one(query, &[&data.email]).await;

    match result {
        Ok(row) => {
            let user_id: i32 = row.get(0);
            let stored_question: String = row.get(2);
            let stored_answer: String = row.get(3);

            // Perbandingan langsung antara answer dari FE dengan stored_answer dari DB
            if stored_question == data.question && data.answer == stored_answer {
                // Encrypt the new password
                let hashed_password = hash(&data.password, DEFAULT_COST).expect("Failed to hash password");

                // Update the password in the database
                let update_password_query = "UPDATE users SET password = $1 WHERE id = $2";
                match client.execute(update_password_query, &[&hashed_password, &(user_id as i32)]).await {
                    Ok(_) => HttpResponse::Ok().body("Password berhasil diperbarui"),
                    Err(e) => {
                        eprintln!("Gagal memperbarui password: {:?}", e);
                        HttpResponse::InternalServerError().finish()
                    }
                }
            } else {
                HttpResponse::Unauthorized().body("Pertanyaan atau jawaban keamanan tidak cocok")
            }
        },
        Err(e) => {
            eprintln!("Gagal mengambil data pengguna: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
async fn login(
    data: web::Json<LoginRequest>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    // Ambil pengguna berdasarkan email
    let query = "SELECT id, password, nama FROM users WHERE email = $1";
    let result = client.query_one(query, &[&data.email]).await;

    match result {
        Ok(row) => {
            let user_id: i32 = row.get(0);
            let hashed_password: String = row.get(1);
            let user_name: String = row.get(2); // Ambil nama pengguna

            // Verifikasi password
            if verify(&data.password, &hashed_password).unwrap_or(false) {
                // Generate token
                let token = create_token(&user_id.to_string(), "your_secret_key").unwrap();

                // Simpan token dan update status pengguna di database
                let update_query = "UPDATE users SET token = $1, status = 'online' WHERE id = $2";
                let update_result = client.execute(update_query, &[&token, &user_id]).await;

                match update_result {
                    Ok(_) => {
                        let response = LoginResponse {
                            id: user_id,
                            token,
                            nama: user_name, // Sertakan nama dalam respons
                        };
                        HttpResponse::Ok().json(response) // Send response as JSON
                    },
                    Err(e) => {
                        eprintln!("Gagal menyimpan token atau memperbarui status: {:?}", e);
                        HttpResponse::InternalServerError().finish()
                    }
                }
            } else {
                HttpResponse::Unauthorized().finish()
            }
        },
        Err(e) => {
            eprintln!("Gagal mengambil data pengguna: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

fn create_token(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize + 600; // Token expires in 10 minutes

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?;
    Ok(token)
}

fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let otp: u32 = rng.gen_range(100000..1000000); // Generate a 6-digit OTP
    otp.to_string()
}
async fn verify_otp(
    data: web::Json<VerifyOtp>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let query = "
        SELECT id
        FROM users
        WHERE otp = $1 AND otp_verified = FALSE
    ";
    let result = client.query_one(query, &[&data.otp]).await;

    match result {
        Ok(row) => {
            let user_id: i32 = row.get(0);
            let update_query = "
                UPDATE users
                SET otp_verified = TRUE
                WHERE id = $1
            ";
            let update_result = client.execute(update_query, &[&(user_id as i32)]).await;

            match update_result {
                Ok(_) => HttpResponse::Ok().body("OTP verifikasi berhasil"),
                Err(e) => {
                    eprintln!("Gagal memperbarui status OTP: {:?}", e);
                    HttpResponse::InternalServerError().finish()
                }
            }
        },
        Err(e) => {
            eprintln!("Gagal memverifikasi OTP: {:?}", e);
            HttpResponse::Unauthorized().body("OTP verifikasi gagal")
        }
    }
}

async fn send_email(to: &str, subject: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let email = Message::builder()
        .from("auranisavalent@gmail.com".parse().unwrap())
        .to(to.parse().unwrap())
        .subject(subject)
        .body(body.to_string())
        .unwrap();

    let creds = Credentials::new(
        String::from("auranisavalent@gmail.com"),
        String::from("acdvdizpquvlmovq") // Ganti dengan password aplikasi Anda
    );

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .port(465) // Atau port yang sesuai
        .build();

    // Send email and handle the result
    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(Box::new(e)),
    }
}


async fn get_users(db_client: web::Data<Arc<Mutex<Client>>>) -> impl Responder {
    let client = db_client.lock().await;

    let rows = client
        .query("SELECT * FROM users WHERE otp_verified = TRUE", &[])
        .await;

    match rows {
        Ok(rows) => {
            let users: Vec<User> = rows
                .iter()
                .map(|row| User {
                    id: row.get("id"),
                    nama: row.get("nama"),
                    password: row.get("password"),
                    email: row.get("email"),
                    pekerjaan: row.get("pekerjaan"),
                    tanggal_lahir: row.get("tanggal_lahir"),
                    gender: row.get("gender"),
                    umur: row.get("umur"),
                    goldar: row.get("goldar"),
                    provinsi: row.get("provinsi"), 
                    kabupaten: row.get("kabupaten"), 
                    kecamatan: row.get("kecamatan"),
                })
                .collect();
            HttpResponse::Ok().json(users)
        },
        Err(e) => {
            eprintln!("Failed to fetch users: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
async fn insert_user(
    data: web::Json<NewUser>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;
    let hashed_password = hash(&data.password, DEFAULT_COST).expect("Failed to hash password");
    let otp = generate_otp(); // Fungsi untuk generate OTP

    // Prepare the SQL statement
    let stmt = client
        .prepare(
            "INSERT INTO users (nama, password, email, pekerjaan, tanggal_lahir, gender, umur, goldar, provinsi, kabupaten, kecamatan, otp, otp_verified, question, answer) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, FALSE, $13, $14)"
        )
        .await
        .expect("Failed to prepare statement");

    // Execute the SQL statement
    if let Err(e) = client.execute(&stmt, &[
        &data.nama,
        &hashed_password,
        &data.email,
        &data.pekerjaan,
        &data.tanggal_lahir,
        &data.gender,
        &data.umur,
        &data.goldar,
        &data.provinsi,
        &data.kabupaten,
        &data.kecamatan,
        &otp,
        &data.question,
        &data.answer
    ]).await {
        eprintln!("Failed to execute query: {:?}", e);
        return HttpResponse::InternalServerError().body(format!("Error inserting user: {}", e));
    }

    // Send OTP to user's email
    if let Err(e) = send_email(&data.email, "Your OTP Code", &format!("Your OTP code is: {}", otp)).await {
        eprintln!("Failed to send OTP email: {:?}", e);
        return HttpResponse::InternalServerError().body(format!("Error sending OTP: {}", e));
    }

    HttpResponse::Ok().body("User registered successfully. Please check your email for OTP verification.")
}
async fn update_user(
    data: web::Json<UpdateUser>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let user_id = data.id;

    let mut set_clauses = Vec::new();
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = Vec::new();
    let mut index = 1;

    if let Some(ref nama) = data.nama {
        set_clauses.push(format!("nama = ${}", index));
        params.push(Box::new(nama.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref email) = data.email {
        set_clauses.push(format!("email = ${}", index));
        params.push(Box::new(email.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref pekerjaan) = data.pekerjaan {
        set_clauses.push(format!("pekerjaan = ${}", index));
        params.push(Box::new(pekerjaan.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref tanggal_lahir) = data.tanggal_lahir {
        set_clauses.push(format!("tanggal_lahir = ${}", index));
        params.push(Box::new(tanggal_lahir.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref gender) = data.gender {
        set_clauses.push(format!("gender = ${}", index));
        params.push(Box::new(gender.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref umur) = data.umur {
        set_clauses.push(format!("umur = ${}", index));
        params.push(Box::new(umur) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref goldar) = data.goldar {
        set_clauses.push(format!("goldar = ${}", index));
        params.push(Box::new(goldar.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref provinsi) = data.provinsi {
        set_clauses.push(format!("provinsi = ${}", index));
        params.push(Box::new(provinsi.clone()));
        index += 1;
    }
    if let Some(ref kabupaten) = data.kabupaten {
        set_clauses.push(format!("kabupaten = ${}", index));
        params.push(Box::new(kabupaten.clone()));
        index += 1;
    }
    if let Some(ref kecamatan) = data.kecamatan {
        set_clauses.push(format!("kecamatan = ${}", index));
        params.push(Box::new(kecamatan.clone()));
        index += 1;
    }

    let set_clause = set_clauses.join(", ");
    let query = format!("UPDATE users SET {} WHERE id = ${}", set_clause, index);

    params.push(Box::new(user_id) as Box<dyn tokio_postgres::types::ToSql + Sync>);

    let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params.iter().map(|b| &**b).collect();

    match client.execute(&query, &params_refs[..]).await {
        Ok(_) => HttpResponse::Ok().body("User updated successfully"),
        Err(e) => {
            eprintln!("Failed to update user: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
async fn patch_user(
    user_id: web::Path<i32>,
    data: web::Json<PatchUser>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let user_id = *user_id;

    let mut set_clauses = Vec::new();
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = Vec::new();
    let mut index = 1;

    if let Some(ref nama) = data.nama {
        set_clauses.push(format!("nama = ${}", index));
        params.push(Box::new(nama.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref password) = data.password {
        set_clauses.push(format!("password = ${}", index));
        params.push(Box::new(password.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref email) = data.email {
        set_clauses.push(format!("email = ${}", index));
        params.push(Box::new(email.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref pekerjaan) = data.pekerjaan {
        set_clauses.push(format!("pekerjaan = ${}", index));
        params.push(Box::new(pekerjaan.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref tanggal_lahir) = data.tanggal_lahir {
        set_clauses.push(format!("tanggal_lahir = ${}", index));
        params.push(Box::new(tanggal_lahir.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref gender) = data.gender {
        set_clauses.push(format!("gender = ${}", index));
        params.push(Box::new(gender.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref umur) = data.umur {
        set_clauses.push(format!("umur = ${}", index));
        params.push(Box::new(umur) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref goldar) = data.goldar {
        set_clauses.push(format!("goldar = ${}", index));
        params.push(Box::new(goldar.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
        index += 1;
    }
    if let Some(ref provinsi) = data.provinsi {
    set_clauses.push(format!("provinsi = ${}", index));
    params.push(Box::new(provinsi.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
    index += 1;
    }
    if let Some(ref kabupaten) = data.kabupaten {
    set_clauses.push(format!("kabupaten = ${}", index));
    params.push(Box::new(kabupaten.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
    index += 1;
    }
    if let Some(ref kecamatan) = data.kecamatan {
    set_clauses.push(format!("kecamatan = ${}", index));
    params.push(Box::new(kecamatan.clone()) as Box<dyn tokio_postgres::types::ToSql + Sync>);
    index += 1;
    }


    if set_clauses.is_empty() {
        return HttpResponse::BadRequest().body("Tidak ada field yang diupdate");
    }

    let query = format!(
    "UPDATE users SET {} WHERE id = ${} RETURNING id, nama, password, email, pekerjaan, tanggal_lahir, gender, umur, goldar, provinsi, kabupaten, kecamatan",
    set_clauses.join(", "),
    index
    );
    params.push(Box::new(user_id) as Box<dyn tokio_postgres::types::ToSql + Sync>);

    let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params.iter().map(|p| p.as_ref()).collect();

    match client.query_one(&query, &params_ref).await {
        Ok(row) => {
            let user = User {
                id: row.get("id"),
                nama: row.get("nama"),
                password: row.get("password"),
                email: row.get("email"),
                pekerjaan: row.get("pekerjaan"),
                tanggal_lahir: row.get("tanggal_lahir"),
                gender: row.get("gender"),
                umur: row.get("umur"),
                goldar: row.get("goldar"),
                provinsi: row.get("provinsi"), 
                kabupaten: row.get("kabupaten"), 
                kecamatan: row.get("kecamatan"),
            };
            HttpResponse::Ok().json(user)
        },
        Err(e) => {
            eprintln!("Gagal mengupdate pengguna: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

async fn delete_user(
    data: web::Json<DeleteUser>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let user_id = data.id;

    let result = client
        .execute("DELETE FROM users WHERE id = $1", &[&(user_id as i32)])
        .await;

    match result {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => {
            eprintln!("Gagal menghapus pengguna: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
async fn checkstatus(
    user_id: i32,
    db_client: &Client,
) -> Result<(), tokio_postgres::Error> {
    let query = "SELECT token FROM users WHERE id = $1";
    let row = db_client.query_one(query, &[&user_id]).await?;

    let token: Option<String> = row.get(0);
    if token.is_none() {
        // Jika tidak ada token, set status menjadi offline
        let update_query = "UPDATE users SET status = 'offline' WHERE id = $1";
        db_client.execute(update_query, &[&user_id]).await?;
    }

    Ok(())
}
async fn logout(
    path: web::Path<i32>,
    db_client: web::Data<Arc<Mutex<Client>>>,
) -> impl Responder {
    let user_id = path.into_inner();
    let client = db_client.lock().await;

    println!("Received logout request for user_id: {}", user_id);

    if let Err(e) = checkstatus(user_id, &client).await {
        eprintln!("Gagal memeriksa status pengguna: {:?}", e);
        return HttpResponse::InternalServerError().finish();
    }

    let query = "UPDATE users SET token = NULL, status = 'offline' WHERE id = $1";
    match client.execute(query, &[&user_id]).await {
        Ok(_) => {
            println!("Logout successful for user_id: {}", user_id);
            HttpResponse::Ok().body("Logout berhasil, status pengguna telah diperbarui.")
        },
        Err(e) => {
            eprintln!("Gagal logout atau memperbarui status: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}
#[derive(Serialize)]
struct GetUserById {
    id: i32,
    nama: String,
    email: String,
    pekerjaan: String,
    tanggal_lahir: String,
    gender: String,
    umur: i32,
    goldar: String,
    provinsi: String,
    kabupaten: String,
    kecamatan: String,
}

async fn get_user_by_id(
    path: web::Path<i32>,
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let id = path.into_inner(); // Ekstrak nilai integer dari path
    let client = db_client.lock().await;

    // Query untuk mengambil data pengguna tanpa 'password'
    let query = "SELECT id, nama, email, pekerjaan, tanggal_lahir, gender, umur, goldar, provinsi, kabupaten, kecamatan FROM users WHERE id = $1";
    let result = client.query_one(query, &[&(id as i32)]).await;

    match result {
        Ok(row) => {
            let user = GetUserById {
                id: row.get(0),
                nama: row.get(1),
                email: row.get(2),
                pekerjaan: row.get(3),
                tanggal_lahir: row.get(4),
                gender: row.get(5),
                umur: row.get(6),
                goldar: row.get(7),
                provinsi: row.get(8),
                kabupaten: row.get(9),
                kecamatan: row.get(10),
            };
            HttpResponse::Ok().json(user)
        },
        Err(e) => {
            eprintln!("Gagal mengambil data pengguna: {:?}", e);
            HttpResponse::NotFound().body("Pengguna tidak ditemukan")
        }
    }
}
#[derive(Serialize)]
struct TotalUsersCount {
    count: i64,
}

async fn count_total_users(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let query = "SELECT COUNT(*) FROM users";

    match client.query_one(query, &[]).await {
        Ok(row) => {
            let count: i64 = row.get(0);  // Gunakan i64 untuk BIGINT
            let response = TotalUsersCount { count };
            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            eprintln!("Gagal menghitung total pengguna yang terdaftar: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[derive(Serialize)]
struct VerifiedUsersCount {
    count: i64,
}

async fn count_verified_users(
    db_client: web::Data<Arc<Mutex<Client>>>
) -> impl Responder {
    let client = db_client.lock().await;

    let query = "SELECT COUNT(*) FROM users WHERE otp_verified = TRUE";

    match client.query_one(query, &[]).await {
        Ok(row) => {
            let count: i64 = row.get(0);
            let response = VerifiedUsersCount { count };
            HttpResponse::Ok().json(response)
        },
        Err(e) => {
            eprintln!("Gagal menghitung pengguna yang sudah terverifikasi: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Set up database
    let database_url = "postgres://postgres:auranisa14@localhost:5432/postgres"; // Ganti dengan string koneksi Anda

    let (client, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .expect("Failed to connect to database");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Connection error: {:?}", e);
        }
    });

    let client = Arc::new(Mutex::new(client));
    
    HttpServer::new(move || {
        App::new()
        .wrap(Cors::permissive())
            .app_data(web::Data::new(client.clone()))
            .route("/users/register", web::post().to(insert_user))
            .route("/users/delete", web::delete().to(delete_user))
            .route("/verify_otp", web::post().to(verify_otp))
            .route("/login", web::post().to(login))
            .route("/forgot_password", web::post().to(forgot_password))

            .route("/users/{id}", web::patch().to(patch_user))
            .route("/users/update", web::put().to(update_user))
            .route("/users", web::get().to(get_users))
            .route("/user/{id}", web::get().to(get_user_by_id))
            .route("/users/totaluser", web::get().to(count_total_users))
            .route("/users/userverif", web::get().to(count_verified_users))
            .route("/chart/goldar", web::get().to(get_chartgoldar))
            .route("/count/gender", web::get().to(get_gender_stats))
            .route("/chart/gender", web::get().to(get_chartgender))
            .route("/chart/umur", web::get().to(get_chartumur))
            .route("/chart/job", web::get().to(get_chartjob))
            .route("/logout/{user_id}", web::post().to(logout))
    })
    .bind("127.0.0.1:8082")?
    .run()
    .await
}