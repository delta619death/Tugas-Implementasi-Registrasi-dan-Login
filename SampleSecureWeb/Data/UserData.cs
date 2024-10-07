using System;
using SampleSecureWeb.Models;
using BC = BCrypt.Net.BCrypt;

namespace SampleSecureWeb.Data;

public class UserData : IUser
{
    private readonly ApplicationDbContext _db;

    public UserData(ApplicationDbContext db)
    {
        _db = db;
    }
    public User Login(User user)
{
    var _user = _db.Users.FirstOrDefault(u => u.Username == user.Username);
    if (_user == null)
    {
        throw new Exception("User Not Found");
    }
    // Pastikan user.Password tidak null sebelum melakukan verifikasi
    if (_user.Password == null || !BC.Verify(user.Password, _user.Password))
    {
        throw new Exception("Password is incorrect");
    }
    return _user;
}


    public User Registration(User user)
    {
        try
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            _db.Users.Add(user);
            _db.SaveChanges(); 
            return user;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }
}

