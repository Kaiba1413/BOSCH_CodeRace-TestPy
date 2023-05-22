import os

###############################
# CWE-628: Function Call with Incorrectly Specified Arguments
ADMIN_ROLES = 1
USER_GRANTED_ROLES = 2
def accessGranted(resource, user):
    userRoles = getUserRoles(user)
    return accessGranted(resource, ADMIN_ROLES)

def getUserRoles(user):
    if user == 1: return ADMIN_ROLES
    if user == 2: return USER_GRANTED_ROLES
    return 0

def accessGranted(resource, userRoles):
    # grant or deny access based on user roles
    if (userRoles == ADMIN_ROLES):
        print("Access granted for ADMIN")
    elif (userRoles == USER_GRANTED_ROLES):
        print("Access granted for USER-GRANTED-ROLES")
    else:
        print("Access denied")

###############################
# CWE-1041: Use of Redundant Code
# CWE-561: Dead Code
# CWE-570: Expression is Always False
def calculate_surface_area(s, r):
    pi = 3.14159
    surface_area = 0
    result = 0
    isSValid = False
    isRValid = False

    if(r > 0.0 and s > 0.0):
        isRValid = True
        isSValid = True
        surface_area = pi * r * s + pi * pow(r, 2)
        if (not isSValid):
            print("This is dead code !!!")

    if(r > 1.0 and s > 0.0):
        isRValid = True
        isRValid = True # set wrong variable
        surface_area = pi * r * s + pi * pow(r, 2)
        if (isSValid):
            print("This is also dead code !!!")
    
    if (isRValid and isSValid):
        result = surface_area

    return result

###############################
# CWE-732: Incorrect Permission Assignment for Critical Resource
def create_some_file(filename):
    f = open(filename, "w")
    f.write("Secret phase: YOLO")
    f.close()

    ### issue
    #os.chmod(filename, 0x777)

    ### no issue
    mode = 0x777
    os.chmod(filename, mode)    
