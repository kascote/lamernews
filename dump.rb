# encoding: UTF-8

ROOT_DIR = File.expand_path(File.dirname(__FILE__))
$: << ROOT_DIR

require 'app'
require 'date'
require 'active_support'
require 'active_support/core_ext/string'
require 'active_support/core_ext/date_time/conversions'
require 'sequel'
require 'awesome_print'
require 'uri'

$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r
DB = Sequel.connect(:adapter=>'mysql2', :host=>'localhost', :database=>'nip', :user=>'nip')
NEWS = DB[:news]
USERS = DB[:users]
BODIES = DB[:news_body]

def get_latest_news(start=0,count=100)
    numitems = $r.zcard("news.cron")
    news_ids = $r.zrevrange("news.cron",start,start+(count-1))
    return get_news_by_id(news_ids,:update_rank => true),numitems
end

def get_domain(url)
  return 'text' if url[0..3] == 'text'
  URI.parse(url).host
end

def generate_slug(url)
  slug = I18n.transliterate(url).strip
  slug.tr!(' ,;*?":¿.!¡@#$%&/(){}[]=<>\'',
           '-æææææææ-ææææææææææææææææææ')
  slug.gsub!('æ', '')
  if slug.end_with?('-')
    slug[0..-2]
  else
    slug
  end
end

def dump_news(news)
  news.each do |row|
    domain = get_domain(row['url'])
    nid = NEWS.insert(
        :id               => row['id'],
        :nip_id           => 1,
        :title            => row['title'],
        :source           => domain,
        :url              => domain == 'text' ? 'text' : row['url'],
        :slug             => generate_slug(row['title']),
        :score            => row['score'],
        :rank             => row['rank'],
        :comments_count   => row['comments'],
        :view_count       => 0,
        :up_counter       => row['up'],
        :down_counter     => row['down'],
        :user_id          => row['user_id'],
        :username         => row['username'],
        :created_at       => DateTime.strptime(row['ctime'], '%s').to_s(:db),
        :updated_at       => DateTime.strptime(row['ctime'], '%s').to_s(:db),
      )
    if domain == 'text'
      BODIES.insert(
        :news_id  => nid,
        :body     => row['url'][7..-1]
      )
    end
  end
end

def dump_user(user)
  USERS.insert(
    :id             => user['id'],
    :username       => user['username'],
    :password       => user['password'],
    :salt           => user['salt'],
    :karma          => user['karma'],
    :about          => user['about'],
    :email          => user['email'],
    :flags          => user['flags'],
    :created_at     => DateTime.strptime(user['ctime'], '%s').to_s(:db),
    :updated_at     => DateTime.strptime(user['ctime'], '%s').to_s(:db),
  )
end

def get_news
  numitems = 100
  actual = 0
  batch = 100
  while true
    news, numitems = get_latest_news(actual, batch)
    dump_news(news)
    actual += news.size
    ap news.size
    break if news.size < 100
  end
end

def get_users
  actual = 1
  while actual < 100
    user = $r.hgetall "user:#{actual}"
    dump_user(user) unless user.empty?
    actual += 1
  end
end

get_news
get_users
