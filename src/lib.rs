use rss::{ChannelBuilder, Item};
use serde::{Deserialize, Serialize};
use worker::*;

const UPSTREAM_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KV_NAMESPACE: &str = "EXPLOITED_VULNS_FEED";
const UPSTREAM_KV_KEY: &str = "upstream_response";

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

async fn fetch_upstream() -> Result<CatalogResponse> {
    let url = Url::parse(UPSTREAM_URL)?;
    let response = Fetch::Url(url).send().await;
    match response {
        Ok(mut r) => r.json::<CatalogResponse>().await,
        Err(r) => Err(r)
    }
}

#[event(scheduled)]
pub async fn cron(_event: ScheduledEvent, env: Env, _ctx: worker::ScheduleContext) {
    // These will all panic if they fail, but thaqt shouldn't be terrible for a scheduled task
    let kv = env.kv(KV_NAMESPACE).unwrap();
    let result = fetch_upstream().await.unwrap();
    if let Ok(put) = kv.put(UPSTREAM_KV_KEY, &result) {
        if let Err(pe) = put.execute().await {
            console_log!("Failed updating KV: {}", pe)
        }
    }
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, ctx: worker::Context) -> Result<Response> {
    log_request(&req);

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. Alternatively, use `Router::with_data(D)` to
    // provide arbitrary data that will be accessible in each route via the `ctx.data()` method.
    let router = Router::new();

    // Add as many routes as your Worker needs! Each route will get a `Request` for handling HTTP
    // functionality and a `RouteContext` which you can use to  and get route parameters and
    // Environment bindings like KV Stores, Durable Objects, Secrets, and Variables.
    router
        .get_async("/*rss.xml", |_req, ctx| async move {
            // I'm not sure why, but vulns.json() wants vulns to be mutable
            // There's probably also something better to be done with async here
            let kv = ctx.kv(KV_NAMESPACE)?;
            let kv_response = kv.get(UPSTREAM_KV_KEY).json::<CatalogResponse>().await;
            let response: CatalogResponse = match kv_response {
                Ok(Some(r)) =>  r,
                // If we don't have a KV response, try to fetch from upstream
                // Unwrap will panic here if upstream fetch fails, but we don't
                // have any successful paths forward at that point
                _ => {
                    console_log!("No KV response -- falling back to an upstream fetch");
                    let response = fetch_upstream().await.unwrap();
                    if let Ok(put) = kv.put(UPSTREAM_KV_KEY, &response) {
                        if let Err(pe) = put.execute().await {
                            console_log!("Error while updating KV: {:?}", pe)
                        }
                    }
                    response
                }
            };
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
