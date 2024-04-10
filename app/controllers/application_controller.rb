class ApplicationController < ActionController::API
    before_action :authenticate_request

    # リクエストヘッダーからトークンを抽出するためのやつ
    def extract_token_from_header
        # リクエストヘッダーから 'Authorization' フィールドの値を取得
        header = request.headers['Authorization']
        # ヘッダーが存在する場合、スペースで区切られた最後の要素（つまりトークン）を取得
        token = header&.split(' ')&.last
        puts "Extracted token: #{token}"
        token
    end


    # JWTトークンをデコードしてペイロードを取得
    def decode_token(token)
        # JWT.decode メソッドを使用して、与えられたトークンをデコード
        # 第1引数にはデコードするトークン、第2引数にはシークレットキー
        # 第3引数にはトークンの検証を行うかどうかを示すブール値（true）。
        decoded_token = JWT.decode(token, Rails.application.config.jwt_secret_key, true)
        puts "Decoded token: #{decoded_token.inspect}"
        # デコードされたトークン（ペイロード）が返されます。
        decoded_token
    rescue JWT::DecodeError => e
        puts "Error decoding token: #{e.message}"
        nil
    end

    def generate_jwt_token(user)
        # 与えられたユーザーのIDを含むハッシュ
        payload = { user: user.as_json(only: [:id, :email, :username]) }
        # ペイロードをトークンにエンコード.第1引数にはペイロード、第2引数にはシークレットキーを指定
        # このシークレットーキーはトークンの署名に使用され、トークンの検証時に必要
        JWT.encode(payload, Rails.application.config.jwt_secret_key)
    end

    def current_user
        return @current_user if defined?(@current_user)

        decoded_token = decode_token(extract_token_from_header)
        return nil if decoded_token.blank?

        user_data = decoded_token.first['user']
        @current_user = User.find_by(id: user_data['id'])
    end

    # 認証メソッド
    def authenticate_request
        unless current_user
            render json: { error: 'ログインする必要があります' }, status: :unauthorized
        end
    end

    private
    
    def authenticate_user
        unless current_user
            current_user.present?
        end
    end
end
