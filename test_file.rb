# This is a test file for omamori scan

def vulnerable_method(input)
  eval(input) # Potential code execution vulnerability
end

user_input = gets.chomp
vulnerable_method(user_input)