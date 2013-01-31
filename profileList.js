/*
profileLB = new Bs_Dropdown();
profileLB.imgDir = 'scripts/blueShoes/components/dropdown/img/win2k/';
profileLB.setValue('Default');
profileLB.drawInto('profileLB');
profileLB.attachEvent('onChange', loadProfile);
*/

if(getCookie("profileList")!=null) {
        // load the various profiles
        var a = unescape(getCookie("profileList"));
        var profileListArray = a.split("|");

        for (var i=0; i<profileListArray.length; i++) {
                var option = document.createElement("option");
                option.text = unescape(profileListArray[i]);
                EditableSelect.selectAddOption(document.getElementById("profileLB"), option);

                if(i==0)
                        option.selected="selected";
        }
}
else {
        profileListArray = new Array("Default");

        var option = document.createElement("option");
        option.text = "Default";
        EditableSelect.selectAddOption(document.getElementById("profileLB"), option);
        option.selected="selected";
}
