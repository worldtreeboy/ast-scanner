# Ruby on Rails configuration - INTENTIONALLY VULNERABLE for testing
# These settings should NEVER be used in production

Rails.application.configure do
  # CRITICAL: Debug mode in production
  config.consider_all_requests_local = true
  config.eager_load = false

  # HIGH: Verbose error pages
  config.action_dispatch.show_exceptions = true
  config.action_dispatch.show_detailed_exceptions = true

  # CRITICAL: Weak secret key base
  config.secret_key_base = 'insecure_secret_key_base_for_testing_123'

  # HIGH: Asset debugging enabled
  config.assets.debug = true
  config.assets.compile = true

  # HIGH: Logging sensitive data
  config.log_level = :debug
  config.filter_parameters = []  # Should filter :password, :token, etc.

  # CRITICAL: Mass assignment vulnerability (older Rails)
  # config.active_record.whitelist_attributes = false

  # HIGH: CORS allow all
  config.middleware.insert_before 0, Rack::Cors do
    allow do
      origins '*'
      resource '*', headers: :any, methods: :any, credentials: true
    end
  end

  # HIGH: SSL not enforced
  config.force_ssl = false

  # MEDIUM: Caching disabled (performance/security)
  config.action_controller.perform_caching = false
  config.cache_store = :null_store
end

# CRITICAL: Hardcoded database credentials
database_config = {
  adapter: 'postgresql',
  host: 'localhost',
  database: 'myapp_production',
  username: 'admin',
  password: 'SuperSecretPass123!'
}

# CRITICAL: Hardcoded API keys
API_KEY = 'sk_live_1234567890abcdef'
STRIPE_SECRET = 'sk_live_stripe_secret_key'
AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# HIGH: Unsafe YAML loading (RCE in older Ruby)
# YAML.load(user_input)  # Should use YAML.safe_load

# CRITICAL: Marshal deserialization
# Marshal.load(user_data)  # RCE via gadget chains

# HIGH: ERB template from user input
# ERB.new(user_template).result  # SSTI vulnerability

# CRITICAL: System command execution
# system("ping #{user_input}")  # Command injection
# `ls #{user_input}`  # Command injection via backticks
# exec("cat #{filename}")  # Command injection

# HIGH: SQL injection patterns
# User.where("name = '#{params[:name]}'")  # SQL injection
# User.find_by_sql("SELECT * FROM users WHERE id = #{params[:id]}")
