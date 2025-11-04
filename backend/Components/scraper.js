class Event {
  constructor(time_gmt, time_local, title, text) {
    this.time_gmt = time_gmt;
    this.time_local = time_local;
    this.title = title;
    this.text = text;
  }
}

var events = [];

export async function getLiveEvents() {
  const res = await fetch(
    "https://very-teddi-iad-9839f521.koyeb.app/getRecentEvents"
  );

  if (!res.ok) {
    console.error(`❌ HTTP ${res.status}: ${res.statusText}`);
    return;
  }

  const data = await res.json();

  data.forEach((item) => {
    let event = new Event(
      item.time_gmt,
      item.time_local,
      item.title,
      item.text
    );
    events.push(event);
  });

  console.log("Scraped Events:", events);
  return events;
}
