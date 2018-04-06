<!DOCTYPE html>
<html lang="en">
   <head>
      <title></title>
      <meta charset="UTF-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link rel='icon' href='images/favicon.ico'>
      
      <!-- Libraries -->
      <link href="libs/jqueryUI/jquery-ui.min.css" rel="stylesheet">
      <link href="libs/jqueryUI/theme-smoothness/jquery-ui.min.css" rel="stylesheet">
      <link href="libs/jqueryUI/jquery-ui-autocomplete-category.css" rel="stylesheet">
      <link href="libs/bootstrap/css/bootstrap.min.css" rel="stylesheet">
      <link href="libs/bootstrap/css/bootstrap-select.min.css" rel="stylesheet">
      <link href="libs/bootstrap/css/datepicker3.css" rel="stylesheet">


      <script src="libs/angularjs/angular.js"></script>
      <script src="libs/jquery/jquery.js"></script>
      <script src="libs/jqueryUI/jquery-ui.min.js"></script>
      <script src="libs/jqueryUI/jquery-ui-autocomplete-category.js"></script>
      <script src="libs/jqueryCookie/jquery.cookie.js"></script>
      <script src="libs/bootstrap/js/bootstrap.min.js"></script>
      <script src="libs/bootstrap/js/bootstrap-select.min.js"></script>
      <script src="libs/bootstrap/js/bootstrap-datepicker.js"></script>

      <!-- Non-Library Files -->
      <link href="css/default.css" rel="stylesheet">
      <link href="css/search.css" rel="stylesheet">

      <script src="js/variables.js"></script>
      <script src="js/default.js"></script>
      <script src="js/search.js"></script>

   </head>
   <body>

      <header class="container">
         <div id="headerContainer" class="container">
            
            <a id="logoContainer" href="#">
               <img id="logo" src="images/American_Automobile_Association_logo.png" alt="AAA" />
               <span id="title"></span>
            </a>

            <div id="signInButton" class="" data-toggle="modal" data-target="#loginModal"><a href="#">Sign In</a></div>
            
            <div id="profileWrapper">
               <div id="profileNameWrapper">
                  Welcome, <label id="profileName">Guest</label> <span class="caret"></span>
               </div>
               
               <div id="profileDivider"></div>
            
               <div id="signOutButton" class="" ><a href="#">Sign Out</a></div>
            </div>
               
         </div>
      </header>

      <div id="pageContainer" class="container">

            <!-- Sign-In form  -->
            <div id="loginModal" class="modal fade bs-example-modal-sm" tabindex="-1" role="dialog" aria-labelledby="mySmallModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-sm">
                    <div class="modal-content" id="signInForm">
                        <form class="form-signin"  id="loginForm" method="get">       
                            <h2 class="form-signin-heading">Please Login</h2>
                            <input type="text" class="form-control" name="textinput" id="loginName" placeholder="E-mail" required="true" />
                            <input type="password" class="form-control" name="passwordinput" id="loginPwd" placeholder="Password" required=""/>  

                            <button class="btn btn-lg btn-primary btn-block" id="login_button"  type="submit">Login</button>   
                        </form>
                    </div>
                </div>
            </div> 
            <!-- End Sign-In form  -->

            <!-- Register form  -->
            <div id="registerModal" class="modal fade bs-example2-modal-sm" tabindex="-1" role="dialog" aria-labelledby="mySmallModalLabel" aria-hidden="true">
                <div class="modal-dialog modal-sm">
                    <div class="modal-content" id="registerForm">
                        <form class="form-signinin"  id="registerFormID" method="get">       
                            <h2 class="form-signin-heading">Please Register</h2>
                            
                            <input type="text" class="form-control" name="emailinput" id="email" placeholder="Email Address" required="" />
                            <input type="password" class="form-control" name="passwordinput" id="regPwd" placeholder="Password" required=""/>  
                             <input type="password" class="form-control" name="confirmpasswordinput" id="confirmRegPwd" placeholder="Confirm Password" required=""/>  

                            <button class="btn btn-lg btn-primary btn-block" id="clickevent2"  type="submit">Login</button>   
                        </form>
                    </div>
                </div>
            </div>  
            <!-- End Register form  -->


                <!-- Column with main search and frequent searches. -->
                <div class="col-lg-12" style="margin-top:0px;">

                    <div id="searchBar" class="row">

                        <!-- Main search. -->
                        <div class="col-lg-6">

                            <div id="searchWrapper" class="input-group">
                                <input id="searchInput" type="text" class="form-control" placeholder="Search Word">
                                <span id="searchButtonSpan" class="input-group-btn">
                                    <button id="searchButton" class="btn btn-default label-danger" type="button">
                                        <span class="glyphicon glyphicon-search white"></span>
                                    </button>
                                </span>
                            </div>
                           
                                <div id='aaa_enterprise_search_widget_searchAdvanced'>
                                   <a href='#' style="color:white;text-decoration:underline;">Advanced Search</a>
                                </div>

                        </div>

                        <div class="col-lg-3" style="padding-top:15px;">
                            <input type="checkbox" id="withinSearch" name="withinSearch" disabled="disabled" />
                            <label for="withinSearch">Search Within Results</label>
                        </div>

                        <div class="col-lg-3" style="padding-top:15px;">
                            <span class="glyphicon glyphicon-floppy-disk"></span>
                            <label for="withinSearch">Save Search</label>
                        </div>

                    </div>


                        <!-- Filter searches. -->
                        <div id="narrowResults" class="col-lg-3 row" style="margin-top:0px;background:#D7D7D7;">
                            <h4 class="sectionTitle">Narrow Your Results</h4>

                            <div id="narrowResultsList">

                                 <div class="">
                                    <div class="narrowResultsTitle">Creation Date Range</div>
                                    <div id="checkbox_date_div">
                                        <span class="input-group">
                                            <input type="radio" id="checkbox_date_last_3_months" name="checkbox_date_last" value = "3"/>
                                            <label for="checkbox_date_last_3_months">Last 3 months</label>
                                        </span>
                                        <span class="input-group">
                                            <input type="radio" id="checkbox_date_last_6_months" name="checkbox_date_last" value = "6"/>
                                            <label for="checkbox_date_last_6_months">Last 6 months</label>
                                        </span>
                                        <span class="input-group">
                                            <input type="radio" id="checkbox_date_last_1_year" name="checkbox_date_last" value = "12"/>
                                            <label for="checkbox_date_last_1_year">Last 1 year</label>
                                        </span>
                                        <span class="input-group">
                                            <input type="radio" id="checkbox_date_last_2_years" name="checkbox_date_last" value = "24"/>
                                            <label for="checkbox_date_last_2_years">Last 2 years</label>
                                        </span>

                                        <div class="col-lg-6 col-alpha">
                                            <span>Start</span>
                                            <input id="filter_date_start" class="form-control" />
                                        </div>
                                        <div class="col-lg-6 col-omega">
                                            <span>End</span>
                                            <input id="filter_date_end" class="form-control" />
                                        </div>
                                    </div>
                                </div>
                                 <div class="">
                                    <div class="narrowResultsTitle">Categories</div>
                                    <div id="categoriesList"></div>
                                </div>
								<div class="">
                                    <div class="narrowResultsTitle">Topics</div>
                                    <div id="topicsList"></div>
                                </div>
                            </div>
                            
                        </div>

                        <div id="resultsAndFilterWrapper" class="" style="">

                            <div id="searchAddons" class="col-lg-12" style="color:white;">
                                <label id="resultCount">0</label> result(s) for: 
                            </div>


                            <div id="sortByAndResultCount" class="col-lg-8">
                               <label for="sortBy" style="color:white;">Sort By</label>
                               <select id="sortBySelect">
                               	  <option value="" selected="selected"/>
                                  <option value="name">Name</option>
                                  <option value="date">Date</option>
                               </select>
                               
                               <label for="resultsPerPage" style="color:white;">Results Per Page</label>
                               <select id="resultsPerPageSelect">
                                  <option value="5">5</option>
                                  <option value="10" selected="selected">10</option>
                                  <option value="15">15</option>
                                  <option value="20">20</option>
                                  <option value="25">25</option>
                               </select>
                            </div>

                            <div class="col-lg-4" style="text-align:right;">
                               <label for="pageInput" style="color:white;">Page</label>
                                <input id="pageInput" value="1" style="width:35px;text-align:center;" /> 
                                <label style="color:white;">of <span id="pagesCount">&nbsp;</span></label>

                                <button id='pagination_prev' type="button" class="btn btn-default btn-sm">
                                    <span class="glyphicon glyphicon-arrow-left"></span>
                                </button>
                                <button id='pagination_next' type="button" class="btn btn-default btn-sm">
                                    <span class="glyphicon glyphicon-arrow-right"></span>
                                </button>

                            </div>


                            <div id="searchResults" class="col-lg-12">
                                <!-- Dynamically populated -->
                            </div>

                        </div>

                </div>


      </div>

      <footer class="footer">
         <div id="footerContainer" class="container">
            <div class="navbar-header">
               <a id="copyrightMessage" href="#"></a>
            </div>

            <div id="footerLinks" class="">
               <a href="#">NEED HELP?</a>
               <a href="#">PRIVACY POLICY</a>
            </div>
         </div>
      </footer>

   </body>
</html>
