from seleniumbase import BaseCase
from faker import Faker

fake = Faker()

class TestPosts(BaseCase):
  def test_create_and_list(self):
    self.open('http://localhost:5000/auth/register')
    username = fake.name()
    self.type('input[name="username"]', username)
    self.type('input[name="password"]', "12345678")
    self.click('input[value="Register"]')
    self.type('input[name="username"]', username)
    self.type('input[name="password"]', "12345678")
    self.click('input[value="Log In"]')
    self.click_link("New")
    title = fake.sentence()
    body = fake.sentence()
    self.type('input[name="title"]', title)
    self.type('textarea[name="body"]', body)
    self.click('input[value="Save"]')
    self.assert_text(title)
    self.assert_text(body)