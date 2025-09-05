from seleniumbase import BaseCase
from faker import Faker

fake = Faker()
class TestAuth(BaseCase):
  def test_registration_and_login(self):
    self.open('http://localhost:5000/auth/register')
    username = fake.name()
    self.type('input[name="username"]', username)
    self.type('input[name="password"]', "12345678")
    self.click('input[value="Register"]')
    self.type('input[name="username"]', username)
    self.type('input[name="password"]', "12345678")
    self.click('input[value="Log In"]')
    self.assert_text(username)
    self.assert_text("Log Out")
