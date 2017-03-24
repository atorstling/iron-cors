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
