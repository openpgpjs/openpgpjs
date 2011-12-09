
unittests.register("Example test", function() {
	var result = new Array();
	
	result[0] = new test_result("test1 - testing on (\"str\" == \"str\")", ("str" == "str"));
	result[1] = new test_result("test2 - testing on (1 == 2)", (1 == 2));
	return result;
});
