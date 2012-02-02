# encoding: UTF-8
require 'app_config'
require 'rubygems'
require 'hiredis'
require 'redis'
require 'digest/sha1'
require 'digest/md5'
require 'pbkdf2'

# Turn the password into an hashed one, using PBKDF2 with HMAC-SHA1
# and 160 bit output.
def hash_password(password,salt)
    p = PBKDF2.new do |p|
        p.iterations = PBKDF2Iterations
        p.password = password
        p.salt = salt
        p.key_length = 160/8
    end
    p.hex_string
end

def get_rand
    rand = "";
    File.open("/dev/urandom").read(20).each_byte{|x| rand << sprintf("%02x",x)}
    rand
end

$r = Redis.new(:host => RedisHost, :port => RedisPort) if !$r

if !$r.exists("username.to.id:#{ARGV[0]}")
  puts  'usuario no existe'
  exit 255
end

if ARGV[1].nil?
  puts 'falta la clave'
  exit 255
end


id = $r.get("username.to.id:#{ARGV[0]}")
#user = $r.hgetall("user:#{id}") # get user by id
salt = get_rand

$r.hmset( "user:#{id}",
          "password", hash_password(ARGV[1],salt),
          "salt", salt
        )

