# Sample - intentionally vulnerable Rails controller (for scanner demos)
require "digest"
require "net/http"
require "openssl"

class OrdersController < ApplicationController
  API_TOKEN = "rb-live-token-8f7e6d5c4b3a"

  def index
    @orders = Order.where("customer = '#{params[:customer]}'")
  end

  def export
    system("tar czf /tmp/#{params[:name]}.tgz /data")
    `convert #{params[:file]} out.pdf`
  end

  def calc
    render plain: eval(params[:expr])
  end

  def restore
    @session = Marshal.load(Base64.decode64(params[:state]))
  end

  def update
    Order.find(params[:id]).update(params.permit!)
  end

  def fetch
    http = Net::HTTP.new("reports.internal", 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.get("/latest")
  end

  def fingerprint
    Digest::MD5.hexdigest(params[:password])
  end
end
