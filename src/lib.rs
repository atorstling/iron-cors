/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate iron;
extern crate unicase;

use iron::{AfterMiddleware, headers};
use iron::method::Method;
use iron::method::Method::*;
use iron::prelude::*;
use iron::status::Status;
use unicase::UniCase;

pub type CORSEndpoint = (Vec<Method>, String);

pub struct CORS {
    // Only endpoints listed here will allow CORS.
    // Endpoints containing a variable path part can use ':foo' like in:
    // "/foo/:bar" for a URL like https://domain.com/foo/123 where 123 is
    // variable.
    pub allowed_endpoints: Vec<CORSEndpoint>,
}

impl CORS {
    #[allow(dead_code)]
    pub fn new(endpoints: Vec<CORSEndpoint>) -> Self {
        CORS { allowed_endpoints: endpoints }
    }

    pub fn is_allowed(&self, req: &mut Request) -> bool {
        let mut is_cors_endpoint = false;
        for endpoint in self.allowed_endpoints.clone() {
            let (methods, path) = endpoint;

            if !methods.contains(&req.method) && req.method != Method::Options {
                continue;
            }

            let path: Vec<&str> = if path.starts_with('/') {
                path[1..].split('/').collect()
            } else {
                path[0..].split('/').collect()
            };

            if path.len() != req.url.path().len() {
                continue;
            }

            for (i, req_path) in req.url
                    .path()
                    .iter()
                    .enumerate() {
                is_cors_endpoint = false;
                if *req_path != path[i] && !path[i].starts_with(':') {
                    break;
                }
                is_cors_endpoint = true;
            }
            if is_cors_endpoint {
                break;
            }
        }
        is_cors_endpoint
    }

    pub fn add_headers(res: &mut Response) {
        res.headers.set(headers::AccessControlAllowOrigin::Any);
        res.headers.set(headers::AccessControlAllowHeaders(
            vec![
                UniCase(String::from("accept")),
                UniCase(String::from("authorization")),
                UniCase(String::from("content-type"))
            ]
        ));
        res.headers.set(headers::AccessControlAllowMethods(vec![Get, Post, Put, Delete]));
    }
}

impl AfterMiddleware for CORS {
    fn after(&self, req: &mut Request, mut res: Response) -> IronResult<Response> {
        if req.method == Method::Options {
            res = Response::with(Status::Ok);
        }

        if self.is_allowed(req) {
            CORS::add_headers(&mut res);
        }

        Ok(res)
    }

    fn catch(&self, req: &mut Request, mut err: IronError) -> IronResult<Response> {
        if self.is_allowed(req) {
            CORS::add_headers(&mut err.response);
        }
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    extern crate router;
    extern crate hyper;
    use iron::Listening;
    use self::router::Router;
    use iron::prelude::*;
    use iron::status;
    use self::hyper::Client;
    use self::hyper::header::Headers;
    use std::io::Read;
    use iron::headers::{Origin, AccessControlRequestMethod, AccessControlAllowOrigin,
                        AccessControlAllowHeaders, AccessControlMaxAge, AccessControlAllowMethods};
    use iron::method::Method;
    use super::CORS;
    use std::str::FromStr;

    struct AutoServer {
        listening: Listening,
        port: u16,
    }

    impl AutoServer {
        pub fn new() -> AutoServer {
            let mut router = Router::new();
            let handler = |_: &mut Request| Ok(Response::with((status::ImATeapot, "")));
            let cors = CORS::new(vec![(vec![Method::Get, Method::Post], "a".to_owned())]);
            router.get("/a", handler, "get_a");
            let mut chain = Chain::new(router);
            chain.link_after(cors);
            let l = Iron::new(chain).http(format!("localhost:0")).unwrap();
            let p = l.socket.port();
            AutoServer {
                listening: l,
                port: p,
            }
        }
    }

    impl Drop for AutoServer {
        fn drop(&mut self) {
            // Workaround for https://github.com/hyperium/hyper/issues/338
            self.listening.close().unwrap();
        }
    }

    #[test]
    fn normal_request_possible() {
        let server = AutoServer::new();
        let client = Client::new();
        let res = client.get(&format!("http://127.0.0.1:{}/a", server.port)).send().unwrap();
        assert_eq!(res.status, status::ImATeapot);
    }

    #[test]
    fn preflight_without_origin_is_bad_request() {
        let server = AutoServer::new();
        let client = Client::new();
        let mut headers = Headers::new();
        headers.set(AccessControlRequestMethod(Method::Get));
        let mut res = client.request(Method::Options,
                                     &format!("http://127.0.0.1:{}/a", server.port))
            .headers(headers)
            .send()
            .unwrap();
        assert_eq!(res.status, status::BadRequest);
        let mut payload = String::new();
        res.read_to_string(&mut payload).unwrap();
        assert_eq!(payload, "Preflight request without Origin header");
    }

    #[test]
    fn preflight_with_origin_accepts_same_origin() {
        let server = AutoServer::new();
        let client = Client::new();
        let mut headers = Headers::new();
        headers.set(AccessControlRequestMethod(Method::Get));
        headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
        let res = client.request(Method::Options,
                                 &format!("http://127.0.0.1:{}/a", server.port))
            .headers(headers)
            .send()
            .unwrap();
        assert_eq!(res.status, status::Ok);
        let allow_origin = res.headers.get::<AccessControlAllowOrigin>().unwrap();
        assert_eq!(format!("{}", allow_origin), "http://www.a.com:8080");
        let allow_headers = res.headers.get::<AccessControlAllowHeaders>().unwrap();
        assert_eq!(format!("{}", allow_headers),
                   "Content-Type, X-Requested-With");
        let allow_methods = res.headers.get::<AccessControlAllowMethods>().unwrap();
        assert_eq!(format!("{}", allow_methods), "GET, PUT, POST");
        let max_age = res.headers.get::<AccessControlMaxAge>().unwrap();
        assert_eq!(max_age.0, 60 * 60u32);
    }

    #[test]
    fn normal_request_allows_origin() {
        let server = AutoServer::new();
        let client = Client::new();
        let mut headers = Headers::new();
        headers.set(Origin::from_str("http://www.a.com:8080").unwrap());
        let res = client.get(&format!("http://127.0.0.1:{}/a", server.port))
            .headers(headers)
            .send()
            .unwrap();
        assert_eq!(res.status, status::ImATeapot);
        let allow_origin = res.headers.get::<AccessControlAllowOrigin>().unwrap();
        assert_eq!(format!("{}", allow_origin), "*");
        assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
        assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
        assert!(res.headers.get::<AccessControlMaxAge>().is_none());
    }

    #[test]
    fn normal_request_without_origin_is_passthrough() {
        let server = AutoServer::new();
        let client = Client::new();
        let res = client.get(&format!("http://127.0.0.1:{}/a", server.port)).send().unwrap();
        assert_eq!(res.status, status::ImATeapot);
        assert!(res.headers.get::<AccessControlAllowOrigin>().is_none());
        assert!(res.headers.get::<AccessControlAllowHeaders>().is_none());
        assert!(res.headers.get::<AccessControlAllowMethods>().is_none());
        assert!(res.headers.get::<AccessControlMaxAge>().is_none());
    }

}
