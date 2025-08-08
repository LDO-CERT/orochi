(function() {
  var template = Handlebars.template, templates = Handlebars.templates = Handlebars.templates || {};
templates['dump'] = template({"1":function(container,depth0,helpers,partials,data) {
    return "        <i class=\"fab fa-linux me-1\"></i>\n";
},"3":function(container,depth0,helpers,partials,data) {
    return "        <i class=\"fab fa-windows me-1\"></i>\n";
},"5":function(container,depth0,helpers,partials,data) {
    return "        <i class=\"fab fa-apple me-1\"></i>\n";
},"7":function(container,depth0,helpers,partials,data) {
    return "        <i class=\"fas fa-robot me-1\"></i>\n";
},"compiler":[8,">= 4.3.0"],"main":function(container,depth0,helpers,partials,data) {
    var stack1, helper, alias1=depth0 != null ? depth0 : (container.nullContext || {}), alias2=container.hooks.helperMissing, alias3="function", alias4=container.escapeExpression, lookupProperty = container.lookupProperty || function(parent, propertyName) {
        if (Object.prototype.hasOwnProperty.call(parent, propertyName)) {
          return parent[propertyName];
        }
        return undefined
    };

  return "\n<li class=\"list-group-item\">\n    <label class=\"check_container\" data-index=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":3,"column":47},"end":{"line":3,"column":56}}}) : helper)))
    + "\" data-color=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"color") || (depth0 != null ? lookupProperty(depth0,"color") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"color","hash":{},"data":data,"loc":{"start":{"line":3,"column":70},"end":{"line":3,"column":79}}}) : helper)))
    + "\">\n"
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias2).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Linux",{"name":"ifeq","hash":{},"fn":container.program(1, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":4,"column":8},"end":{"line":6,"column":17}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias2).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Windows",{"name":"ifeq","hash":{},"fn":container.program(3, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":7,"column":8},"end":{"line":9,"column":17}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias2).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Mac",{"name":"ifeq","hash":{},"fn":container.program(5, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":10,"column":8},"end":{"line":12,"column":17}}})) != null ? stack1 : "")
    + ((stack1 = (lookupProperty(helpers,"ifeq")||(depth0 && lookupProperty(depth0,"ifeq"))||alias2).call(alias1,(depth0 != null ? lookupProperty(depth0,"operating_system") : depth0),"Other",{"name":"ifeq","hash":{},"fn":container.program(7, data, 0),"inverse":container.noop,"data":data,"loc":{"start":{"line":13,"column":8},"end":{"line":15,"column":17}}})) != null ? stack1 : "")
    + "\n        <abbr title=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"name") || (depth0 != null ? lookupProperty(depth0,"name") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"name","hash":{},"data":data,"loc":{"start":{"line":17,"column":21},"end":{"line":17,"column":29}}}) : helper)))
    + "\">"
    + alias4(((helper = (helper = lookupProperty(helpers,"name") || (depth0 != null ? lookupProperty(depth0,"name") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"name","hash":{},"data":data,"loc":{"start":{"line":17,"column":31},"end":{"line":17,"column":39}}}) : helper)))
    + "</abbr>\n\n        <input type=\"checkbox\">\n        <span class=\"checkmark\"></span>        \n\n        <div class=\"btn-group float-end\" role=\"group\">\n            <a href=\"/hex_view/"
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":23,"column":31},"end":{"line":23,"column":40}}}) : helper)))
    + "\" class=\"btn btn-outline-dark hex-index btn-sm\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Hex View\" >\n                <i class=\"fas fa-asterisk\"></i>\n            </a>\n            <button type=\"button\" class=\"btn btn-outline-info info-index btn-sm\" data-index=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":26,"column":93},"end":{"line":26,"column":102}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Dump Info\" >\n                <i class=\"fas fa-info\"></i>\n            </button>\n            <button type=\"button\" class=\"btn btn-outline-danger remove-index btn-sm\" data-index=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":29,"column":97},"end":{"line":29,"column":106}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Delete Dump\" >\n                <i class=\"fas fa-trash\"></i>\n            </button>\n            <button type=\"button\" class=\"btn btn-outline-success edit-index btn-sm\" data-index=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":32,"column":96},"end":{"line":32,"column":105}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Edit Dump\" >\n                <i class=\"fas fa-edit\"></i>\n            </button>\n            <button type=\"button\" class=\"btn btn-outline-warning restart-index btn-sm\" data-index=\""
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":35,"column":99},"end":{"line":35,"column":108}}}) : helper)))
    + "\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Restart Auto Plugin\" >\n                <i class=\"fas fa-backward\"></i>\n            </button>\n            <button type=\"button\" class=\"btn btn-outline-dark download_obj download-index btn-sm\" data-path=\"/media/"
    + alias4(((helper = (helper = lookupProperty(helpers,"index") || (depth0 != null ? lookupProperty(depth0,"index") : depth0)) != null ? helper : alias2),(typeof helper === alias3 ? helper.call(alias1,{"name":"index","hash":{},"data":data,"loc":{"start":{"line":38,"column":116},"end":{"line":38,"column":125}}}) : helper)))
    + "/linux-sample-1.bin\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"Download Dump\" >\n                <i class=\"fas fa-file-download\"></i>\n            </button>\n        </div>\n    </label>\n</li>\n\n";
},"useData":true});
})();
