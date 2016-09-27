require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class EngineOauth2 < OmniAuth::Strategies::OAuth2

      option :name, "engine_oauth2"

      uid{ raw_info['principal']['id'] }

      info do
        {
          name:       raw_info['principal']['name'] + " " + raw_info['principal']['surname'],
          email:      raw_info['principal']['email'],
          nickname:   raw_info['principal']['username'],
          first_name: raw_info['principal']['name'],
          last_name:  raw_info['principal']['surname'],
          admin:      raw_info['principal']['userAuthorities'].include?("ROLE_ADMIN")
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def token_params
        p "token_params is ran"
        params = {:headers => {'Authorization' => authorization(client.id, client.secret, 'Basic') }}
        options.token_params.merge(options_for("token")).merge(params)
      end

      def raw_info
        p "raw_info is ran"
        @raw_info ||= access_token.get('/user', :params => {'access_token' => access_token.token }).parsed
        p @raw_info
      end

      def authorization(client_id, client_secret, header_format)
        header_format + ' ' + Base64.encode64(client_id + ':' + client_secret).delete("\n")
      end
      
    end
  end
end

OmniAuth.config.add_camelization "engine", "Engine"
