use serde_json::json;
// use worker::response::Response;
use rss::{ChannelBuilder, Item};
use serde::{Deserialize, Serialize};
use worker::*;

const UPSTREAM_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// See https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
// for the definition of these structs
// There's probably even a way to hand those definitions directly to serde, but
// I haven't looked
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    #[serde(rename = "cveID")]
    cve_id: Option<String>,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    required_action: String,
    due_date: String,
    notes: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResponse {
    catalog_version: String,
    date_released: String,
    count: u16,
    vulnerabilities: Vec<Vulnerability>,
}

pub fn make_cve_link(cve: String) -> String {
    format!("https://nvd.nist.gov/vuln/detail/{}", cve)
}

pub fn response_from_xml(xml: impl AsRef<str>) -> Result<Response> {
    let mut headers = Headers::new();
    headers.set("content-type", "text/xml")?;

    let data = xml.as_ref().as_bytes().to_vec();
    if let Ok(response) = Response::from_body(ResponseBody::Body(data)) {
        let mut headers = Headers::new();
        headers.set("content-type", "text/xml")?;
        Ok(response.with_headers(headers))
    } else {
        Err(Error::Json(("Could not build response".into(), 500)))
    }
}

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

async fn fetch_upstream() -> Result<Response> {
    let url = Url::parse(UPSTREAM_URL)?;
    Fetch::Url(url).send().await
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    log_request(&req);

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. Alternatively, use `Router::with_data(D)` to
    // provide arbitrary data that will be accessible in each route via the `ctx.data()` method.
    let router = Router::new();

    // Add as many routes as your Worker needs! Each route will get a `Request` for handling HTTP
    // functionality and a `RouteContext` which you can use to  and get route parameters and
    // Environment bindings like KV Stores, Durable Objects, Secrets, and Variables.
    router
        .get("/", |_, _| Response::ok("Hello from Workers! And new!"))
        .post_async("/form/:field", |mut req, ctx| async move {
            if let Some(name) = ctx.param("field") {
                let form = req.form_data().await?;
                match form.get(name) {
                    Some(FormEntry::Field(value)) => {
                        return Response::from_json(&json!({ name: value }))
                    }
                    Some(FormEntry::File(_)) => {
                        return Response::error("`field` param in form shouldn't be a File", 422);
                    }
                    None => return Response::error("Bad Request", 400),
                }
            }

            Response::error("Bad Request", 400)
        })
        .get("/worker-version", |_, ctx| {
            let version = ctx.var("WORKERS_RS_VERSION")?.to_string();
            Response::ok(version)
        })
        .get_async("/feed.json", |_, _| async move { fetch_upstream().await })
        .get_async("/rss.xml", |_, _| async move {
            // let mut item = Item::default();
            // item.set_title("Some exploited vulnerability".to_string());
            // item.set_link("https://cisa.gov".to_string());
            // let items = vec![item];
            // I'm not sure why, but vulns.json() wants vulns to be mutable
            // There's probably also something better to be done with async here
            let mut vulns = fetch_upstream().await?;
            let response = vulns.json::<CatalogResponse>().await?;
            let mut items: Vec<Item> = Vec::new();
            for vuln in response.vulnerabilities {
                let mut item = Item::default();
                item.set_title(vuln.vulnerability_name);
                item.set_description(vuln.short_description);
                item.set_pub_date(vuln.date_added);
                if let Some(cve) = vuln.cve_id {
                    item.set_link(make_cve_link(cve));
                }
                items.push(item);
            }
            // In-place sort
            // Make sure things are sorted for to have the newest items at the
            // beginning of the feed
            // b compares a instead of a comparing b to reverse the order
            items.sort_by(|a, b| b.pub_date.cmp(&a.pub_date));
            let channel = ChannelBuilder::default()
                .title("CISA Exploited Vulnerabilities")
                // TODO This should be calculated from the workers env
                .link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
                .description("RSS feed of the CISA exploited vulnerabilities list")
                .pub_date(response.date_released.clone())
                // TODO Once we build in a cron, this should be the last fetch date
                .last_build_date(response.date_released.clone())
                .items(items)
                .build()
                .unwrap();
            response_from_xml(channel.to_string())
        })
        .run(req, env)
        .await
}
