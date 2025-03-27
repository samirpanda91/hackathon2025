import snowflake.connector

# Snowflake REST API endpoint


# Establish a connection
conn = snowflake.connector.connect(
    user=SNOWFLAKE_USER,
    password=SNOWFLAKE_PASSWORD,
    account=SNOWFLAKE_ACCOUNT,
    database=SNOWFLAKE_DATABASE,
    schema=SNOWFLAKE_SCHEMA,
    warehouse=SNOWFLAKE_WAREHOUSE,
    role=SNOWFLAKE_ROLE  # Optional
)

# Create a cursor object
cur = conn.cursor()

# Define your SQL query
query = "SELECT CURRENT_VERSION();"

# Execute the query
cur.execute(query)

# Fetch all results
results = cur.fetchall()

# Print the results
for row in results:
    print(row)

# Close cursor and connection
cur.close()
conn.close()
