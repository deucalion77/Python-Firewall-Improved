import redis
import ipaddress

# Connect to Redis server
r = redis.Redis(host='localhost', port=6379, decode_responses=True)


# Validation
def validation(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Function to add a firewall query
def add_firewall_query(action, port, source_ip, destination_ip):
    if not validation(source_ip):
        print(f"Invalid source IP: {source_ip}")
        return
    
    if not validation(destination_ip):
        print(f"Invalid destination IP: {destination_ip}")
        return
   
    query_id = r.incr('firewall:query:id')
    r.hset(f'firewall:query:{query_id}', mapping={
        'action': action,
        'port': port,
        'source_ip': source_ip,
        'destination_ip': destination_ip
    })
    print(f"Added firewall query ID {query_id}")



# Function to retrieve a firewall query by ID
def get_firewall_query(query_id):
    query = r.hgetall(f'firewall:query:{query_id}')
    if query:
        print(f"Firewall Query ID {query_id}: {query}")
    else:
        print(f"No firewall query found with ID {query_id}.")

# Function to delete a firewall query by ID
def delete_firewall_query(query_id):
    result = r.delete(f'firewall:query:{query_id}')
    if result:
        print(f"Deleted firewall query ID {query_id}")
    else:
        print(f"No firewall query found with ID {query_id} to delete.")

# Main loop to accept user input
def main():
    while True:
        print("\nChoose an action:")
        print("1. Add Firewall Query")
        print("2. Get Firewall Query by ID")
        print("3. Delete Firewall Query by ID")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            # Add a firewall query
            action = input("Enter action (e.g., ALLOW/DENY): ")
            port = input("Enter port number: ")
            source_ip = input("Enter source IP: ")
            destination_ip = input("Enter destination IP: ")
            add_firewall_query(action, port, source_ip, destination_ip)

        elif choice == '2':
            # Get a firewall query by ID
            query_id = input("Enter the firewall query ID to retrieve: ")
            get_firewall_query(query_id)

        elif choice == '3':
            # Delete a firewall query by ID
            query_id = input("Enter the firewall query ID to delete: ")
            delete_firewall_query(query_id)

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
