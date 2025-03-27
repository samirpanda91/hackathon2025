import os
from snowflake import connector
from urllib.parse import urlparse

def connect_to_snowflake_with_proxy(
    user,
    password,
    account,
    warehouse=None,
    database=None,
    schema=None,
    role=None,
    proxy_host=None,
    proxy_port=None,
    proxy_user=None,
    proxy_password=None
):
    """
    Connect to Snowflake using a proxy server.
    
    Args:
        user: Snowflake username
        password: Snowflake password
        account: Snowflake account identifier
        warehouse: Snowflake warehouse (optional)
        database: Snowflake database (optional)
        schema: Snowflake schema (optional)
        role: Snowflake role (optional)
        proxy_host: Proxy server hostname or IP
        proxy_port: Proxy server port
        proxy_user: Proxy username (optional)
        proxy_password: Proxy password (optional)
    """
    # Configure proxy settings
    proxy_config = {
        'host': proxy_host,
        'port': proxy_port
    }
    
    if proxy_user and proxy_password:
        proxy_config['user'] = proxy_user
        proxy_config['password'] = proxy_password
    
    # Set up connection parameters
    conn_params = {
        'user': user,
        'password': password,
        'account': account,
        'authenticator': 'snowflake',  # or 'externalbrowser' for SSO
    }
    
    # Optional parameters
    if warehouse:
        conn_params['warehouse'] = warehouse
    if database:
        conn_params['database'] = database
    if schema:
        conn_params['schema'] = schema
    if role:
        conn_params['role'] = role
    
    # Set proxy in connection parameters
    conn_params['proxy_host'] = proxy_host
    conn_params['proxy_port'] = proxy_port
    if proxy_user and proxy_password:
        conn_params['proxy_user'] = proxy_user
        conn_params['proxy_password'] = proxy_password
    
    try:
        # Establish connection
        connection = connector.connect(**conn_params)
        print("Successfully connected to Snowflake!")
        
        # Test the connection
        cursor = connection.cursor()
        cursor.execute("SELECT CURRENT_VERSION()")
        version = cursor.fetchone()[0]
        print(f"Snowflake version: {version}")
        
        return connection
        
    except Exception as e:
        print(f"Error connecting to Snowflake: {str(e)}")
        raise

# Example usage
if __name__ == "__main__":
    # Get credentials from environment variables (recommended for security)
    SNOWFLAKE_USER = os.getenv('SNOWFLAKE_USER', 'your_username')
    SNOWFLAKE_PASSWORD = os.getenv('SNOWFLAKE_PASSWORD', 'your_password')
    SNOWFLAKE_ACCOUNT = os.getenv('SNOWFLAKE_ACCOUNT', 'your_account')
    
    # Proxy configuration
    PROXY_HOST = os.getenv('PROXY_HOST', 'proxy.company.com')
    PROXY_PORT = os.getenv('PROXY_PORT', '3128')  # Common proxy ports: 3128, 8080
    PROXY_USER = os.getenv('PROXY_USER', None)  # Set if proxy requires authentication
    PROXY_PASSWORD = os.getenv('PROXY_PASSWORD', None)
    
    # Connect to Snowflake
    connection = connect_to_snowflake_with_proxy(
        user=SNOWFLAKE_USER,
        password=SNOWFLAKE_PASSWORD,
        account=SNOWFLAKE_ACCOUNT,
        warehouse='COMPUTE_WH',
        database='SNOWFLAKE_SAMPLE_DATA',
        schema='TPCH_SF1',
        role='SYSADMIN',
        proxy_host=PROXY_HOST,
        proxy_port=PROXY_PORT,
        proxy_user=PROXY_USER,
        proxy_password=PROXY_PASSWORD
    )
    
    # Don't forget to close the connection when done
    if connection:
        connection.close()