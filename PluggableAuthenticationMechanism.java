package AuthenticationMechanism;

import java.util.ArrayList;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
/*
Visitor for Visitor Pattern. It will declare Visit method for each class of UserCollection
 */
interface Visitor{
    /*
    @param k_user allows to Visit to access KerberosUser
     */
    public boolean Visit(KerberosUser k_user);
    /*
    @param l_user allows to Visit to access LocalUser
     */
    public boolean Visit(LocalUser l_user);
    /*
    @param ldap_user allows to Visit to access LDAPUser
     */
    public boolean Visit(LDAPUser ldap_user);
}
/*
Client for Visitor Pattern
It will trigger searching operations by using Visitor Pattern
Target for Adapter Pattern
Abstract Class for Adapter Class
It defines abstract authenticate and getUid method to be defined by its subclass later
 */
abstract class OperatingSystem{
    public User user;
    //it will be iterated thorough
    public UserCollection userCollection;

    //authenticate will be defined in the Adapter class
    abstract int authenticate(String name, String pwd);
    //getUid will be defined in Adapter class
    abstract int getUid(String name);

    //defineType will be used to categorize the returns of Accept method. Now it has a default number.
    private static int defineType=10;

    //We find the user's type with the help of the Accept method defined in LocalUser,KerberosUser and LDAPUser
    //Visitor method returns the value of 1 for kerberos user, 2 for ldap user and 3 for local user

    /*
    It is the template method of this class. When user wants to enter the system, it will call this method
     */
    public void login(){
        controlStarted();
        //defineType will collect the results of visitor methods
        defineType= user.Accept(new LocalVisitor());
                    user.Accept(new LDAPVisitor());
                    user.Accept(new KerborosVisitor());

        String name = user.getName();
        String pwd =  user.getPwd();
        boolean found = false;
        //CollectionIterator will iterate thorough the userCollection
        CollectionIterator itr= new CollectionIterator(userCollection);
        for(itr.First();!itr.IsDone();itr.Next()) {
            //name and password of user that wants to login to system will compared with the records
            if(itr.CurrentUser().getName()==user.getName() && itr.CurrentUser().getPwd() == user.getPwd()) {
                System.out.println(""+itr.CurrentUser().getName()+" FOUND IN THE LIST");
                found = true;
                break;
            }
        }
        //if user is not found in the list do not try to authenticate!
        if(!found) {
            System.out.println("User not found!");
        }
        //if user is in the list do authenticate!
        else {
            int rc = authenticate(name, pwd);
            if (rc == 0){ //success
                //  System.out.println(defineType+"(1:Kerberos, 2:Ldap , 3:Local)\n-SUCCESSFULLY LOGGED IN-");
                System.out.println("SUCCESSFULLY LOGGED IN");
                int uid= getUid(name);
                setUid(uid);
                System.out.println(uid);
            }
        }
    }

    public static int setUid(int uid){
        return uid;
    }
    private String getPassword() {
        return "password";
    }

    private String getName() {
        return "name";
    }

    //concrete template methods
    //it only informs user
    protected void controlStarted(){
        System.out.println();
        System.out.println("__System starts for checking user__ ");
    }

    //it will collect the results from Concrete Elements(KerberosUser, LocalUser, LDAPUser)
    // it will used in Adapter Class for categorizing users.
    public static int getDefinetype() {
        return defineType;
    }

}
/*
Adapter Class
It adapts Target to Adaptees
 */
class Adapter extends OperatingSystem{
    private final int  DEFAULT_NUMBER = -1;
    /*
    @param name will be replaced with user's name
    @param pwd is for user's password
    return will categorize the user and direct it the right authentication of right adaptee, if it cant
    then method will return DEFAULT_NUMBER
     */
    public int authenticate(String name, String pwd) {
        if(getDefinetype()==1){
            return KerberosAdaptee.getKerberosAdaptee().krb_authenticate(name, pwd);
        }
        else if(getDefinetype()==2){
            return LDAPAdaptee.getLdapAdaptee().ldap_authenticate(name, pwd);
        }
        else if(getDefinetype()==3){
            return LocalAdaptee.getLocalAdaptee().local_authenticate(name, pwd);
        }

        return DEFAULT_NUMBER;
    }
    /*
    @param name is for user name
    getUid will categorize the user and direct it the right adaptee, if it cant then method will return DEFAULT_NUMBER
    uid will be defined in related adaptee class
     */
    public int getUid(String name) {

        if(getDefinetype()==1) {
            return KerberosAdaptee.getKerberosAdaptee().krb_getuid(name);
        }
        else if(getDefinetype()==2) {
            return LDAPAdaptee.getLdapAdaptee().ldap_getuid(name);
        }
        else if(getDefinetype()==3) {
            return LocalAdaptee.getLocalAdaptee().local_getuid(name);
        }

        return DEFAULT_NUMBER;
    }

}

/*
KERBEROS
This is Adaptee 1
It will specialize authentication and getUid method according to itself
 */
class KerberosAdaptee {
    private static KerberosAdaptee kerberos_adaptee=null;
    public static KerberosAdaptee getKerberosAdaptee() {
        if(kerberos_adaptee==null) {
            kerberos_adaptee= new KerberosAdaptee();
        }
        return kerberos_adaptee;

    }
    public int krb_authenticate(String name, String pwd){
        System.out.println(name+" is a Kerberos user.");
        return 0;
    }
    public int krb_getuid(String name){
        int uid = ThreadLocalRandom.current().nextInt();
        System.out.print(name+"'s Kerberos uid:");
        return uid;
    }

}

/*
LOCAL
This is Adaptee 2
It will specialize authentication and getUid method according to itself
 */
class LocalAdaptee {
    private static LocalAdaptee local_adaptee=null;
    public static LocalAdaptee getLocalAdaptee() {
        if(local_adaptee==null) {
            local_adaptee= new LocalAdaptee();
        }
        return local_adaptee;
    }
    public int local_authenticate(String name,String pwd) {
        System.out.println(name+" is a Local user.");
        return 0;
    }
    public int local_getuid(String name){
        int uid = ThreadLocalRandom.current().nextInt();
        System.out.print(name+"'s Local uid:");
        return uid;
    }
}
/*
LDAP
This is Adaptee 3
It will specialize authentication and getUid method according to itself
 */
class LDAPAdaptee{
    private static LDAPAdaptee ldap_adaptee = null;

    public static LDAPAdaptee getLdapAdaptee() {
        if(ldap_adaptee==null) {
            ldap_adaptee=new LDAPAdaptee();
        }
        return ldap_adaptee;
    }
    public int ldap_authenticate(String name,String pwd) {
        System.out.println(name+" is a LDAP user.");
        return 0;
    }
    public int ldap_getuid(String name){
        int uid = ThreadLocalRandom.current().nextInt();
        System.out.print(name+"'s LDAP uid:");
        return uid;
    }
}

/*
User is Element for Visitor Pattern
It defines abstract accept method
 */
abstract class User{
    private String name;
    private String pwd;
    private int uid; //User has uid , but user cant set his uid by himself


    /*
    visitor element methodu
    @param visitor
     */
    abstract int Accept(Visitor visitor);

    //user constructor
    public User(String name, String pwd){
        this.name
                = name;
        this.pwd = pwd;
    }
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name
                = name;
    }

    public String getPwd() {
        return pwd;
    }

    public void setPwd(String pwd) {
        this.pwd = pwd;
    }

}


/*
ConcreteElement 1 for Visitor Pattern
 */
class KerberosUser extends User{
    /*
    @param visitor
    return 1 if user is defined in Kerberos
     */
    @Override
    int Accept(Visitor visitor) {
        visitor.Visit(this);
        return 1;  //It returns defineType to OperatingSystem
    }

    //constructor
    public KerberosUser(String name, String pwd) {
        super(name, pwd);
    }
}

/*
ConcreteElement 2 for Visitor Pattern
 */
class LDAPUser extends User{
    /*
    @param visitor
    return 2 if user is defined in LDAP
     */
    @Override
    int Accept(Visitor visitor) {
        visitor.Visit(this);
        return 2;  //It returns defineType to OS
    }

    //constructor
    public LDAPUser(String name, String pwd) {
        super(name, pwd);
    }
}

/*
ConcreteElement 3 for Visitor Pattern
it implements an Accept operation that takes a visitor as an argument
 */
class LocalUser extends User{

    /*
    @param visitor
    return 3 if user is defined in Local
     */
    @Override
    int Accept(Visitor visitor) {
        visitor.Visit(this);
        return 3;  //It returns defineType to OS
    }

    //constructor
    public LocalUser(String name, String pwd) {
        super(name, pwd);
    }
}
