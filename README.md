# illumino - firewall - challenge

#### Folder Structure
1. src -- contains source codee
2. tst -- contains testing logicc
3. pom.xml -- gets dependencies from maven
4. testCSV.csv -- csv file with multiple firewall rules. Used by testing logic

#### How to run
1. Install maven -- https://maven.apache.org/install.html
2. Run mvn clean package

#### Design Considerations
1. I designed a trie data structure (binary) to store and quickly search existing rules associated with different IP addresses
2. I used multiple tries (4 - one for each direction and each protocol)
3. The idea was to reduce the search time (i.e. firewall latency)

#### Potential Issues
1. The tries could easily get skewed and hog up all the memory on the system, especially for sparse IP address spaces 
2. I could have invested more into an optimized version of tries to ensure that the tries are always balanced


##### Teams in order of preference

1. Policy Team
2. Platform Team
3. Data Team (intrigued -- would love to know more)

#### Interested?
Reach out to me at my email (neha2493@gmail.com) or my linkedin (https://www.linkedin.com/in/kuneha/) profile. 