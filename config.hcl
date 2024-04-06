# Sample configuration. I am just trying to visualize how this would work.

provider x500 "my-directory" {

    # Properties available for all providers.
    # This limits what auth mechanisms this provider will provide.
    only_auth_mechs = ["PLAIN"]

    # Properties specific to X.500
    bind = true
    compare = true
    otp_attribute = [2,5,4,238]
    display_name_attribute = [2,5,4,239]

}