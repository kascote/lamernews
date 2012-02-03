# encoding: UTF-8
require 'app'
require 'ap'

$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r


def show_user
  if !$r.exists("username.to.id:#{ARGV[0]}")
    puts  'usuario no existe'
    exit 255
  end

  id = $r.get("username.to.id:#{ARGV[0]}")
  user = $r.hgetall("user:#{id}") # get user by id

  ap user
end

def index_url
  numitems = $r.zcard("news.cron")

  puts numitems
  0.step(numitems, 10) do |item|
    puts item
    news,eles = get_latest_news(item,10)
    news.each do |n|
      hh = OpenSSL::Digest::SHA1.new(n['url']).to_s
      puts "#{hh} - #{$r.sismember('news:url', hh)}"
      $r.sadd('news:url', hh)
    end
    puts "=============================="
  end
end

index_url

