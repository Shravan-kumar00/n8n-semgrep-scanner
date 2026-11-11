class SafeController < ApplicationController
  PASSWORD = ENV.fetch("DB_PASSWORD")

  def index
    @orders = Order.where(customer: params[:customer])
    @more = Order.where("customer = ?", params[:customer])
  end

  def export
    system("tar", "czf", "/tmp/out.tgz", params[:name])
    system("uptime")
  end

  def update
    Order.find(params[:id]).update(params.require(:order).permit(:status))
  end

  def fingerprint
    Digest::SHA256.hexdigest(params[:data])
  end
end
