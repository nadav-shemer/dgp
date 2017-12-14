                         / Dgp /

                 Determinstically Generated Passwords


    ~ What is Dgp?

      A sqlite powered wrapper for:
      pbkdf2_hex(seed+secret, service_name, iterations=8192)
      and other password output formats (base58, xkcd, etc.)

    ~ How do I use it?

      1. edit the configuration in the factory.py file or
         export a DGP_SETTINGS environment variable
         pointing to a configuration file or pass in a
         dictionary with config values using the create_app
         function.

      2. install the app from the root of the project directory

         pip install --editable .

      3. instruct flask to use the right application

         export FLASK_APP="dgp.factory:create_app()"

      4. initialize the database with this command:

         flask initdb

      4b. Write a seed file:

         echo "My seed which I also wrote down somewhere safe" > seed

      5. now you can run dgp:

         flask run

         the application will greet you on
         http://localhost:5000/

    ~ Is it tested?

      Nope :)
      Run `python setup.py test` to see the old tests fail.
