drop table if exists entries;
create table entries (
  id integer primary key autoincrement,
  name text not null,
  type text not null,
  note text not null
);
