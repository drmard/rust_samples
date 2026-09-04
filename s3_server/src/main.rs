use async_trait::async_trait;
use bytes::Bytes;
use s3s::dto::*;
use s3s::{S3Error, S3Result, S3};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;

// the structure of in-memory storage
struct InMemoryS3 {

    // storage: Bucket_name -> (File_name -> Data)
    buckets: Mutex<HashMap<String, HashMap<String, Bytes>>>,
}

#[async_trait]
impl S3 for InMemoryS3 {

    async fn create_bucket(&self, req: CreateBucketInput) -> S3Result<CreateBucketOutput> {
        let mut buckets = self.buckets.lock().unwrap();
        
        if buckets.contains_key(&req.bucket) {
            return Err(S3Error::new(s3s::s3_error!(BucketAlreadyExists)));
        }
        
        buckets.insert(req.bucket.clone(), HashMap::new());
        println!("Bucket '{}' successfully created", req.bucket);
        
        Ok(CreateBucketOutput::default())
    }

    // loading object
    async fn put_object(&self, req: PutObjectInput) -> S3Result<PutObjectOutput> {
        let mut buckets = self.buckets.lock().unwrap();
        
        let bucket = buckets.get_mut(&req.bucket).ok_or_else(|| {
            S3Error::new(s3s::s3_error!(NoSuchBucket))
        })?;

        // Collecting bytes from the request body stream
        let body_stream = req.body.ok_or_else(|| S3Error::new(s3s::s3_error!(InvalidRequestBody)))?;
        let data = body_stream.collect_to_bytes().await.map_err(|e| {
            println!("Error reading body: {:?}", e);
            S3Error::new(s3s::s3_error!(InternalError))
        })?;

        bucket.insert(req.key.clone(), data);
        println!("File '{}' uploaded to bucket '{}'", req.key, req.bucket);

        Ok(PutObjectOutput::default())
    }

    async fn get_object(&self, req: GetObjectInput) -> S3Result<GetObjectOutput> {
        let buckets = self.buckets.lock().unwrap();
        
        let bucket = buckets.get(&req.bucket).ok_or_else(|| {
            S3Error::new(s3s::s3_error!(NoSuchBucket))
        })?;

        let data = bucket.get(&req.key).ok_or_else(|| {
            S3Error::new(s3s::s3_error!(NoSuchKey))
        })?;

        println!("file '{}' requested from bucket '{}'", req.key, req.bucket);

        // convert bytes to stream for answer
        let body = s3s::Body::from(data.clone());

        Ok(GetObjectOutput {
            body: Some(body),
            content_length: Some(data.len() as i64),
            ..GetObjectOutput::default()
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    // initialize logs
    tracing_subscriber::fmt::init();

    // create an instance of S3 service
    let s3_impl = InMemoryS3 {
        buckets: Mutex::new(HashMap::new()),
    };

    // wrap it in an S3Service using the built-in builder from the s3s library
    let mut s3_provider = s3s::service::S3ServiceBuilder::new(s3_impl);
    
    // Enable support for anonymous requests (without mandatory AWS signature validation).
    s3_provider.set_auth(s3s::auth::SimpleAuth::new("access_key", "secret_key"));
    let s3_service = s3_provider.build().into_shared();

    // start TCP listener on localhost:8014
    let addr = SocketAddr::from(([127, 0, 0, 1], 8014));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("S3 compatible server running at http://{}", addr);

    // incoming HTTP connection processing cycle
    loop {
        let (stream, _) = listener.accept().await?;
        let s3_service = s3_service.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, s3_service)
                .await
            {
                eprintln!("Error processing connection: {:?}", err);
            }
        });
    }
}
