//! Dump what a database actually contains. A diagnostic for the reverse-DNS
//! path, which is invisible from the command surface.

fn main() {
    let path = std::env::args().nth(1).expect("usage: dbdump <db>");
    let conn = rusqlite::Connection::open(&path).expect("open");

    println!("--- dns_obs by source ---");
    let mut stmt = conn
        .prepare("SELECT source, rtype, COUNT(*) FROM dns_obs GROUP BY source, rtype ORDER BY 1, 2")
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .expect("query");
    for row in rows.flatten() {
        println!("  source={:<10} rtype={:<3} count={}", row.0, row.1, row.2);
    }

    println!("\n--- reverse rows ---");
    let mut stmt = conn
        .prepare("SELECT host, ip FROM dns_obs WHERE source = 'reverse' LIMIT 20")
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .expect("query");
    let mut any = false;
    for row in rows.flatten() {
        any = true;
        println!("  {} -> {}", row.1, row.0);
    }
    if !any {
        println!("  (none)");
    }

    println!("\n--- attribution by method ---");
    let mut stmt = conn
        .prepare(
            "SELECT method, tier, COUNT(*) FROM attribution GROUP BY method, tier ORDER BY 3 DESC",
        )
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .expect("query");
    for row in rows.flatten() {
        println!("  {:<28} tier={:<2} count={}", row.0, row.1, row.2);
    }

    println!("\n--- resolved table ---");
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM resolved", [], |r| r.get(0))
        .expect("query");
    println!("  rows: {n}");
    let mut stmt = conn
        .prepare("SELECT tier, COUNT(*) FROM resolved GROUP BY tier")
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
        .expect("query");
    for row in rows.flatten() {
        println!("  tier={} count={}", row.0, row.1);
    }

    println!("\n--- connections with no attribution ---");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM conn c WHERE NOT EXISTS (SELECT 1 FROM attribution a WHERE a.conn_id = c.id)",
            [],
            |r| r.get(0),
        )
        .expect("query");
    println!("  {count}");
}
