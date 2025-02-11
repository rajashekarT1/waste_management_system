import streamlit as st
import sqlite3
import folium
from streamlit_folium import st_folium
import datetime
import json
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut, GeocoderServiceError
import pandas as pd
import matplotlib.pyplot as plt

# --- DATABASE FUNCTIONS ---

def fetch_users():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")
    users = c.fetchall()
    conn.close()
    return users

def fetch_all_routes():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT id, route_data, collector_username FROM collector_routes")  # Added collector_username
    routes = c.fetchall()
    conn.close()
    return routes

def fetch_collectors():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE role = 'Waste Collector'")
    collectors = [row[0] for row in c.fetchall()]
    conn.close()
    return collectors


def fetch_route_by_id(route_id):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT route_data, collector_username FROM collector_routes WHERE id = ?", (route_id,)) # Added collector_username
    route = c.fetchone()
    conn.close()
    if route:
        return route
    else:
        return None


def create_route(route_data):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO collector_routes (route_data, date_assigned) VALUES (?, ?)", (json.dumps(route_data), datetime.date.today()))
        conn.commit()
        return True  # Indicate success
    except sqlite3.Error as e:
        st.error(f"Error creating route: {e}")
        conn.rollback()
        return False #Indicate failure
    finally:
        conn.close()


def update_route(route_id, route_data):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("UPDATE collector_routes SET route_data = ? WHERE id = ?", (json.dumps(route_data), route_id))
        conn.commit()
        return True # Indicate success
    except sqlite3.Error as e:
        st.error(f"Error updating route: {e}")
        conn.rollback()
        return False # Indicate failure
    finally:
        conn.close()


def delete_route(route_id):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("DELETE FROM collector_routes WHERE id = ?", (route_id,))
        conn.commit()
        return True # Indicate success
    except sqlite3.Error as e:
        st.error(f"Error deleting route: {e}")
        conn.rollback()
        return False #Indicate failure
    finally:
        conn.close()



def assign_route_to_collector(route_id, collector_username):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        # Check if collector already has a route assigned:
        # Existing collector_username check is REMOVED. Let's assume one route per collector only
        c.execute("UPDATE collector_routes SET collector_username = ? WHERE id = ?", (collector_username, route_id))
        conn.commit()
        return True # indicate success
    except sqlite3.Error as e:
        st.error(f"Error assigning route: {e}")
        conn.rollback()
        return False  # indicate failure
    finally:
        conn.close()


def remove_route_from_collector(collector_username):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("UPDATE collector_routes SET collector_username = NULL WHERE collector_username = ?", (collector_username,))
        conn.commit()
        return True
    except sqlite3.Error as e:
        st.error(f"Error removing route assignment: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def create_tables():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('Resident', 'Waste Collector', 'Admin')))''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_username ON users (username)")

    c.execute('''CREATE TABLE IF NOT EXISTS collector_routes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collector_username TEXT,
                    route_data TEXT,
                    date_assigned DATE,
                    FOREIGN KEY (collector_username) REFERENCES users(username))''')

    c.execute('''CREATE TABLE IF NOT EXISTS collection_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    location_id TEXT NOT NULL,
                    collector_username TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('Collected', 'Pending', 'Missed')),
                    image_path TEXT,
                    weight REAL,
                    volume REAL,
                    FOREIGN KEY (collector_username) REFERENCES users(username))''')

    c.execute('''CREATE TABLE IF NOT EXISTS resident_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    location_id TEXT NOT NULL,
                    resident_username TEXT,
                    feedback TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (resident_username) REFERENCES users(username))''')

    c.execute('''CREATE TABLE IF NOT EXISTS issue_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_username TEXT NOT NULL,
                    location_id TEXT,
                    issue_type TEXT,
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'Open',
                    FOREIGN KEY (reporter_username) REFERENCES users(username))''')

    c.execute('''CREATE TABLE IF NOT EXISTS work_schedule (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collector_username TEXT NOT NULL,
                    shift_start DATETIME,
                    shift_end DATETIME,
                    FOREIGN KEY (collector_username) REFERENCES users(username))''')

    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    collector_username TEXT NOT NULL,
                    alert_type TEXT,
                    message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (collector_username) REFERENCES users(username))''')

    conn.commit()
    conn.close()


def register_user(username, password, role):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        st.success("Account created successfully! You can now log in.")
        return True
    except sqlite3.IntegrityError:
        st.error("Username already exists. Try a different one.")
        return False
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")
        return False
    finally:
        conn.close()


def login_user(username, password):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT password, role FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    if user:
        return user[1]
    else:
        st.error("Invalid username or password. Try again.")
        return None


def get_waste_collector_route(username):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT route_data FROM collector_routes WHERE collector_username = ?", (username,))
    route_data = c.fetchone()
    conn.close()
    if route_data:
        return route_data[0]
    else:
        return None

def save_waste_collector_route(username, route_data):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("UPDATE collector_routes SET route_data = ? WHERE collector_username = ?", (json.dumps(route_data), username))
        if c.rowcount == 0: # If the collector has no route yet
            c.execute("INSERT INTO collector_routes (collector_username, route_data, date_assigned) VALUES (?, ?, ?)", (username, json.dumps(route_data), datetime.date.today()))

        conn.commit()
        st.success("Route saved successfully!")
    except sqlite3.Error as e:
        st.error(f"Error saving route: {e}")
        conn.rollback()
    finally:
        conn.close()


def save_collection_status(location_id, collector_username, status, image_path=None, weight=None, volume=None):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute(
            "INSERT INTO collection_logs (location_id, collector_username, timestamp, status, image_path, weight, volume) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (location_id, collector_username, datetime.datetime.now(), status, image_path, weight, volume),
        )
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Error saving collection status: {e}")
        conn.rollback()
    finally:
        conn.close()


def get_resident_feedback(location_id):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT feedback FROM resident_feedback WHERE location_id = ?", (location_id,))
    feedback_data = c.fetchall()
    conn.close()
    return [row[0] for row in feedback_data]

def fetch_collection_logs():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT * FROM collection_logs")
    logs = c.fetchall()
    conn.close()
    return logs

def fetch_issue_reports():
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    c.execute("SELECT * FROM issue_reports")
    reports = c.fetchall()
    conn.close()
    return reports


def show_waste_collector_dashboard():
    st.subheader("Waste Collector Dashboard")
    st.write(f"Welcome, Waste Collector {st.session_state.username}!")

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Dashboard Overview",
        "Route Optimization & Navigation",
        "Collection Reporting & Logs",
        "Issue Reporting",
        "Work Schedule & Attendance"
    ])

    with tab1:
        daily_route_summary()
        realtime_pickup_status()

    with tab2:
        view_assigned_route_on_map()

    with tab3:
        mark_completed_pickups()
        upload_photos_of_collection()
        weight_volume_tracking()

    with tab4:
        report_blocked_overflowing_bins()
        residents_not_following_waste_rules()
        equipment_malfunction()

    with tab5:
        view_weekly_work_schedule()
        clock_in_out_system()



def show_admin_dashboard():
    st.subheader("Admin Dashboard")
    st.write(f"Welcome, Admin {st.session_state.username}!")

    admin_tab1, admin_tab2, admin_tab3 = st.tabs([
        "User Management",
        "Route Management",
        "Reports and Analytics"
    ])

    with admin_tab1:
        manage_users()
    with admin_tab2:
        manage_routes()
    with admin_tab3:
        view_reports()


def daily_route_summary():
    route = get_waste_collector_route(st.session_state.username)
    if route:
        try:
            route_data = json.loads(route)
            st.write("Assigned Route:", ", ".join(route_data))
        except json.JSONDecodeError:
            st.error("Error decoding route data. Data is not valid JSON.")
            st.write("Raw Route Data:", route)
    else:
        st.info("No route assigned for today.")


def realtime_pickup_status():
    if "locations" not in st.session_state:
        st.session_state.locations = []

    new_location = st.text_input("Add New Location", key="new_location_input")
    if st.button("Add Location", key="add_location_button"):
        if new_location and new_location not in st.session_state.locations:
            geolocator = Nominatim(user_agent="waste_management_app", timeout=5)

            try:
                location_info = geolocator.geocode(new_location + ", Hyderabad, Telangana, India")

                if location_info:
                    st.session_state.locations.append(new_location)
                    st.success(f"Location '{new_location}' added!")

                else:
                    st.error(f"Could no        navigation_integration()t find location '{new_location}'. Please enter a valid location in Hyderabad.")

            except GeocoderTimedOut:
                st.error(f"Timeout error: Geocoding service timed out for '{new_location}'. Please try again later.")
            except GeocoderServiceError as e:
                st.error(f"Geocoding service error: {e}. Check your internet connection or try again later.")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")


        elif new_location in st.session_state.locations:
            st.warning(f"Location '{new_location}' already exists.")
        else:
            st.warning("Please enter a location.")

    if st.session_state.locations:
        selected_location = st.selectbox("Select Location", st.session_state.locations, key="realtime_location_select")
        status = st.selectbox("Collection Status", ["Collected", "Pending"], key="realtime_collection_select")

        if st.button("Save Status", key="realtime_save_status"):
            save_collection_status(selected_location, st.session_state.username, status)
            st.success(f"Status for {selected_location} updated to {status}!")
    else:
        st.info("No locations added yet. Add a location above.")



def view_assigned_route_on_map():
    route_data = get_waste_collector_route(st.session_state.username)
    HYDERABAD_COORDINATES = (17.3850, 78.4867)
    geolocator = Nominatim(user_agent="waste_management_app", timeout=5)

    m = folium.Map(location=HYDERABAD_COORDINATES, zoom_start=12) # Initialize the map regardless

    if route_data:
        try:
            route_list = json.loads(route_data)
        except json.JSONDecodeError:
            st.error("Invalid JSON data for route.")
            return

        for location in route_list:
            try:
                geocode_location = geolocator.geocode(location + ", Hyderabad, Telangana, India")

                if geocode_location:
                    folium.Marker([geocode_location.latitude, geocode_location.longitude], popup=location).add_to(m)
                else:
                    st.warning(f"Could not geocode location: {location}")

            except GeocoderTimedOut:
                st.error(f"Timeout error: Geocoding service timed out for '{location}'.")
            except GeocoderServiceError as e:
                st.error(f"Geocoding service error: {e}")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}")

        st_folium(m, width=725, height=500)

    else:
        st.info("No route data available to display on the map.")




def mark_completed_pickups():
    location = st.text_input("Location", key="completed_location_input")

    if st.button("Mark Completed", key="completed_mark_button"):
        save_collection_status(location, st.session_state.username, "Collected")
        st.success(f"Collection logged for {location}")
    else:
        st.write("Enter the location for which the pickup is completed")

def upload_photos_of_collection():
    uploaded_file = st.file_uploader("Upload Photo", type=["jpg", "jpeg", "png"], key="photo_uploader")
    if uploaded_file is not None:
        with open(f"uploads/{uploaded_file.name}", "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success("Photo uploaded successfully!")

def weight_volume_tracking():
    weight = st.number_input("Estimated Weight (kg)", min_value=0.0, key="weight_input")
    volume = st.number_input("Estimated Volume (cubic meters)", min_value=0.0, key="volume_input")
    location = st.text_input("Location", key="weight_volume_location")

    if st.button("Save Weight and Volume", key="weight_volume_save_button"):
        save_collection_status(location, st.session_state.username, 'Collected', None, weight, volume)
        st.success("Weight and volume data saved successfully!")

def report_blocked_overflowing_bins():
    issue_description = st.text_area("Describe the issue", key="blocked_description")
    location = st.text_input("Location", key="blocked_location")
    if st.button("Report Blocked/Overflowing Bins", key="blocked_report_button"):
        # Save to database
        conn = sqlite3.connect("waste_management.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO issue_reports (reporter_username, location_id, issue_type, description) VALUES (?, ?, ?, ?)",
                      (st.session_state.username, location, "Blocked/Overflowing Bin", issue_description))
            conn.commit()
            st.success("Issue reported successfully!")
        except sqlite3.Error as e:
            st.error(f"Error reporting issue: {e}")
            conn.rollback()
        finally:
            conn.close()

def residents_not_following_waste_rules():
    resident_location = st.text_input("Resident Location", key="resident_location")
    improper_disposal_type = st.selectbox("Type of Improper Disposal", ["No Segregation", "Illegal Dumping", "Other"], key="resident_disposal_type")
    if st.button("Report Resident", key="resident_report_button"):
        # Save to database
        conn = sqlite3.connect("waste_management.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO issue_reports (reporter_username, location_id, issue_type, description) VALUES (?, ?, ?, ?)",
                      (st.session_state.username, resident_location, "Resident Improper Disposal", improper_disposal_type))
            conn.commit()
            st.success("Resident reported successfully!")
        except sqlite3.Error as e:
            st.error(f"Error reporting issue: {e}")
            conn.rollback()
        finally:
            conn.close()

def equipment_malfunction():
    equipment_type = st.selectbox("Equipment Type", ["Waste Bin", "Vehicle", "Other"], key="equipment_type")
    malfunction_description = st.text_area("Describe the Malfunction", key="equipment_description")
    if st.button("Report Malfunction", key="equipment_report_button"):
        # Save to database
        conn = sqlite3.connect("waste_management.db")
        c = conn.cursor()
        try:
            c.execute("INSERT INTO issue_reports (reporter_username, location_id, issue_type, description) VALUES (?, ?, ?, ?)",
                      (st.session_state.username, None, f"Equipment Malfunction: {equipment_type}", malfunction_description))
            conn.commit()
            st.success("Malfunction reported successfully!")
        except sqlite3.Error as e:
            st.error(f"Error reporting issue: {e}")
            conn.rollback()
        finally:
            conn.close()

def view_weekly_work_schedule():
    st.write("Weekly Work Schedule (Implementation Required)")


def clock_in_out_system():
    if st.button("Clock In", key="clock_in_button"):
        st.success("Clocked In!")

    if st.button("Clock Out", key="clock_out_button"):
        st.success("Clocked Out!")



def logout_button():
    if st.button("Logout", key="logout_button"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.experimental_rerun()

# --- ADMIN FUNCTIONS ---

def delete_user(user_id):
    conn = sqlite3.connect("waste_management.db")
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        st.success(f"User with ID {user_id} deleted successfully!")
    except sqlite3.Error as e:
        st.error(f"Error deleting user: {e}")
        conn.rollback()
    finally:
        conn.close()
    st.experimental_rerun()


def manage_users():
    st.subheader("Manage Users")

    users = fetch_users()
    if 'user_to_update' not in st.session_state:
        st.session_state.user_to_update = None
    if 'show_add_form' not in st.session_state:
        st.session_state.show_add_form = False

    # Add user form
    if st.session_state.show_add_form:
        with st.form("add_user_form"):
            add_username = st.text_input("New Username")
            add_password = st.text_input("New Password", type="password")
            add_role = st.selectbox("New Role", ["Resident", "Waste Collector", "Admin"])
            submit_add = st.form_submit_button("Create User")
            if submit_add:
                if add_username and add_password and add_role:
                    if register_user(add_username, add_password, add_role):  # Use existing function
                        st.success("User created successfully!")
                    else:
                        st.error("Failed to create user. Check username availability.")
                else:
                    st.warning("Please fill in all fields.")
                st.session_state.show_add_form = False  # hide the form


    # User Selection for Update/Delete
    if users:
        user_options = {user[1]: user[0] for user in users} # Maps username to ID

        # Display users in a dataframe for easier selection
        df = pd.DataFrame(users, columns=["ID", "Username", "Role"])
        st.dataframe(
            df,
            column_config={
                "ID": None,
            },
            hide_index=True,
        )

        selected_username = st.selectbox("Select User for Update/Delete", options=list(user_options.keys()))
        selected_user_id = user_options[selected_username]

        col1, col2 = st.columns(2)

        with col1:
            if st.button("Update User"):
                st.session_state.user_to_update = selected_user_id  #Set user to update to selected user ID
                st.experimental_rerun()

        with col2:
            if st.button("Delete User"):
                delete_user(selected_user_id)

        if st.button("Add User"):
            st.session_state.show_add_form = True

    else:
        st.info("No users found in the database.")

    #Update
    if st.session_state.user_to_update:
        user_id_update = st.session_state.user_to_update
         # Fetch the current user details (replace with your actual database query)
        conn = sqlite3.connect("waste_management.db")
        c = conn.cursor()
        c.execute("SELECT username, role FROM users WHERE id = ?", (user_id_update,))
        user = c.fetchone()
        conn.close()
        if user:
            current_username, current_role = user
            st.subheader(f"Update User: {current_username}")
            with st.form("update_user_form"):
                update_username = st.text_input("Username", value = current_username)
                update_password = st.text_input("Password", type = "password") # Consider Hiding
                update_role = st.selectbox("Role", ["Resident", "Waste Collector", "Admin"], index = ["Resident", "Waste Collector", "Admin"].index(current_role))

                update_submit = st.form_submit_button("Update")
                if update_submit:
                    # Perform the database update here (replace with your actual update query)
                    conn = sqlite3.connect("waste_management.db")
                    c = conn.cursor()
                    try:
                        c.execute("UPDATE users SET username=?, password=?, role=? WHERE id=?", (update_username, update_password, update_role, user_id_update))
                        conn.commit()
                        st.success("User updated successfully!")
                    except sqlite3.Error as e:
                        st.error(f"Error updating user: {e}")
                        conn.rollback()
                    finally:
                        conn.close()
                    # after updating set id again to none so new user show
                    st.session_state.user_to_update = None
                    st.experimental_rerun()
        else:
            st.error("User not found.")

# --- UI FUNCTIONS ---

def show_route_creation_form():
    with st.form("create_route_form"):
        route_name = st.text_input("Route Name")
        location_list = st.text_area("List of Locations (comma-separated)") #Simple text input
        submit_create = st.form_submit_button("Create Route")

        if submit_create:
            locations = [loc.strip() for loc in location_list.split(",")]
            if create_route(locations):
                st.success("Route created successfully!")
            else:
                st.error("Failed to create route.")

def show_route_assignment_form():
    routes = fetch_all_routes()
    collectors = fetch_collectors()

    if not routes:
        st.warning("No routes available. Create a route first.")
        return

    if not collectors:
        st.warning("No waste collectors available. Create a waste collector user first.")
        return


    with st.form("assign_route_form"):
        route_options = {f"Route {route[0]}": route[0] for route in routes} #Route id map

        selected_route_name = st.selectbox("Select Route", options = list(route_options.keys())) #route name

        selected_route_id = route_options[selected_route_name] # get the ID
        selected_collector = st.selectbox("Select Waste Collector", collectors)
        submit_assign = st.form_submit_button("Assign Route")

        if submit_assign:
            if assign_route_to_collector(selected_route_id, selected_collector):
                st.success(f"Route '{selected_route_name}' assigned to {selected_collector}!")
            else:
                st.error("Failed to assign route.")


def show_route_modification_form(route_id):
    route = fetch_route_by_id(route_id)  # Fetch route data

    if not route:
        st.error("Route not found.")
        return

    route_data, assigned_collector = route  # Unpack the tuple

    try:
        existing_locations = json.loads(route_data)
    except json.JSONDecodeError:
        st.error("Invalid route data format.")
        return

    with st.form("modify_route_form"):
        modified_locations = st.text_area("Modified Locations (comma-separated)", ", ".join(existing_locations))
        submit_modify = st.form_submit_button("Modify Route")

        if submit_modify:
            new_locations = [loc.strip() for loc in modified_locations.split(",")]
            if update_route(route_id, new_locations):
                st.success("Route modified successfully!")
            else:
                st.error("Failed to modify route.")

# --- MAIN FUNCTION (manage_routes) ---
def manage_routes():
    st.subheader("Manage Routes")
    if 'show_route_creation' not in st.session_state:
        st.session_state.show_route_creation = False
    if 'show_route_assignment' not in st.session_state:
        st.session_state.show_route_assignment = False
    if 'show_route_modification' not in st.session_state:
        st.session_state.show_route_modification = False

    routes = fetch_all_routes()

    if not routes:
        st.info("No routes defined yet.")
    else:

        #Display routes in a DataFrame

        route_df = pd.DataFrame(routes, columns = ["ID", "Route Data", "Assigned Collector"]) # Added Assigned Collector
        st.dataframe(route_df)


        selected_route_id = st.selectbox("Select Route to Modify", options = [route[0] for route in routes], index = 0)


        col1, col2, col3 = st.columns(3)


        with col1:

            if st.button("Create Route"):
                st.session_state.show_route_creation = True

        with col2:
            if st.button("Assign Route to Collector"):
                st.session_state.show_route_assignment = True
        with col3:
            if st.button("Modify Route"):
                st.session_state.show_route_modification = True



    #Conditional forms using state
    if  st.session_state.show_route_creation:
        show_route_creation_form()

    if  st.session_state.show_route_assignment:
        show_route_assignment_form()


    if  st.session_state.show_route_modification:
        show_route_modification_form(selected_route_id)


def view_reports():
    st.subheader("Reports and Analytics")

    report_type = st.selectbox("Select Report Type", ["Collection Statistics", "Issue Reports", "Weight/Volume Analysis"])

    if report_type == "Collection Statistics":
        collection_stats_report()
    elif report_type == "Issue Reports":
        issue_reports_report()
    elif report_type == "Weight/Volume Analysis":
        weight_volume_report()


def collection_stats_report():
    logs = fetch_collection_logs()
    if not logs:
        st.info("No collection logs available.")
        return

    df = pd.DataFrame(logs, columns=["ID", "Location ID", "Collector Username", "Timestamp", "Status", "Image Path", "Weight", "Volume"])
    st.dataframe(df)

    # Basic Summary Stats
    st.write("### Summary Statistics")
    st.write(f"Total Collections Logged: {len(df)}")
    st.write(f"Number of 'Collected' entries: {len(df[df['Status'] == 'Collected'])}")
    st.write(f"Number of 'Pending' entries: {len(df[df['Status'] == 'Pending'])}")
    st.write(f"Number of 'Missed' entries: {len(df[df['Status'] == 'Missed'])}")

    # Collections by Collector (Bar Chart)
    collector_counts = df['Collector Username'].value_counts()
    fig, ax = plt.subplots()
    collector_counts.plot(kind='bar', ax=ax)
    ax.set_xlabel("Waste Collector")
    ax.set_ylabel("Number of Collections")
    ax.set_title("Collections per Waste Collector")
    st.pyplot(fig)

    # Collection Status Distribution (Pie Chart)
    status_counts = df['Status'].value_counts()
    fig, ax = plt.subplots()
    ax.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax.set_title("Collection Status Distribution")
    st.pyplot(fig)


def issue_reports_report():
    reports = fetch_issue_reports()

    if not reports:
        st.info("No issue reports found.")
        return

    df = pd.DataFrame(reports, columns=["ID", "Reporter Username", "Location ID", "Issue Type", "Description", "Timestamp", "Status"])
    st.dataframe(df)

    # Basic Stats
    st.write("### Summary Statistics")
    st.write(f"Total Issue Reports: {len(df)}")
    st.write(f"Number of 'Open' issues: {len(df[df['Status'] == 'Open'])}")
    st.write(f"Number of 'Closed' issues: {len(df[df['Status'] != 'Open'])}")

    # Issues by Type (Bar Chart)
    issue_counts = df['Issue Type'].value_counts()
    fig, ax = plt.subplots()
    issue_counts.plot(kind='bar', ax=ax)
    ax.set_xlabel("Issue Type")
    ax.set_ylabel("Number of Reports")
    ax.set_title("Issue Reports by Type")
    st.pyplot(fig)

    # Issue Status Distribution (Pie Chart)
    status_counts = df['Status'].value_counts()
    fig, ax = plt.subplots()
    ax.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')
    ax.set_title("Issue Report Status Distribution")
    st.pyplot(fig)


def weight_volume_report():
    logs = fetch_collection_logs()
    if not logs:
        st.info("No collection logs available.")
        return

    df = pd.DataFrame(logs, columns=["ID", "Location ID", "Collector Username", "Timestamp", "Status", "Image Path", "Weight", "Volume"])

    # Filter out rows where Weight or Volume is NaN/None
    df = df.dropna(subset=['Weight', 'Volume'])

    if df.empty:
        st.info("No collection logs with weight and volume data available.")
        return
    st.dataframe(df)
    # Basic Stats
    st.write("### Summary Statistics")
    st.write(f"Average Weight: {df['Weight'].mean():.2f} kg")
    st.write(f"Average Volume: {df['Volume'].mean():.2f} cubic meters")
    st.write(f"Total Weight Collected: {df['Weight'].sum():.2f} kg")
    st.write(f"Total Volume Collected: {df['Volume'].sum():.2f} cubic meters")

    # Weight Distribution (Histogram)
    fig, ax = plt.subplots()
    ax.hist(df['Weight'], bins=20)
    ax.set_xlabel("Weight (kg)")
    ax.set_ylabel("Frequency")
    ax.set_title("Weight Distribution of Collected Waste")
    st.pyplot(fig)

    # Volume Distribution (Histogram)
    fig, ax = plt.subplots()
    ax.hist(df['Volume'], bins=20)
    ax.set_xlabel("Volume (cubic meters)")
    ax.set_ylabel("Frequency")
    ax.set_title("Volume Distribution of Collected Waste")
    st.pyplot(fig)

# --- MAIN APP ---
st.title("♻️ Waste Management System")
create_tables()

# Initialize session state
if "page" not in st.session_state:
    st.session_state.page = "Login"
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "role" not in st.session_state:
    st.session_state.role = None
if "update_button" not in st.session_state:
    st.session_state["update_button"] = 0
if "delete_button" not in st.session_state:
    st.session_state["delete_button"] = 0


if not st.session_state.logged_in:
    if st.session_state.page == "Login":
        st.subheader("Login to Your Account")
        username = st.text_input("Username")
        password = st.text_input("Password", type='password')
        if st.button("Login"):
            role = login_user(username, password)
            if role:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = role
                st.success(f"Welcome {username}, logged in as {role}")
                st.experimental_rerun()
        if st.button("Register"):
            st.session_state.page = "Register"
            st.experimental_rerun()

    elif st.session_state.page == "Register":
        st.subheader("Create an Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type='password')
        role = st.selectbox("Select Role", ["Resident", "Waste Collector", "Admin"])
        if st.button("Register"):
            register_user(new_user, new_password, role)

        if st.button("Login"):
            st.session_state.page = "Login"
            st.experimental_rerun()

if st.session_state.logged_in:
    if st.session_state.role == "Resident":
        st.info("Accessing Resident Dashboard...")
    elif st.session_state.role == "Waste Collector":
        show_waste_collector_dashboard()
    elif st.session_state.role == "Admin":
        show_admin_dashboard()
    else:
        st.error("Unknown role.")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.session_state.page = "Login"
        st.experimental_rerun()