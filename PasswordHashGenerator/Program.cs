using Microsoft.AspNetCore.Identity;

var hasher = new PasswordHasher<TestUser>();

string password = "TestPassword@123";

string hash = hasher.HashPassword(
	new TestUser(),
	password
);

Console.WriteLine("Generated Password Hash:");
Console.WriteLine(hash);

public class TestUser
{
}