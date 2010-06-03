//gcc -o gst t.c `pkg-config --cflags --libs gstreamer-0.10`
#include <gst/gst.h>
 
static void
add_pad (GstElement *element , GstPad *pad , gpointer data){
 
	gchar *name;
	GstElement *sink = (GstElement*)data;
 
	name = gst_pad_get_name(pad);
	gst_element_link_pads(element , name , sink , "sink");
	g_free(name);
}
 
static gboolean
bus_watch(GstBus *bus , GstMessage *msg , gpointer data)
{
    GMainLoop *loop = (GMainLoop *) data;
    if(GST_MESSAGE_TYPE(msg) == GST_MESSAGE_EOS){
        g_main_loop_quit(loop);
    }
    return TRUE;
}
 
void
play_file(const char *filename){
 
	GMainLoop *loop;
	GstElement *pipeline;
	GstBus *bus;
	GstElement *source , *parser , *sink;
 
	loop = g_main_loop_new(NULL , TRUE);
 
	pipeline = gst_pipeline_new("audio-player");
 
	source = gst_element_factory_make("filesrc" , "source");
	parser = gst_element_factory_make("wavparse" , "parser");
	sink = gst_element_factory_make("alsasink" , "output");
 
	g_object_set(G_OBJECT(source) , "location"
			, filename , NULL);
 
	bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
	gst_bus_add_watch(bus , bus_watch , loop);
	g_object_unref(bus);
 
	gst_bin_add_many(GST_BIN(pipeline)
			, source , parser , sink , NULL);
 
	g_signal_connect(parser
			, "pad-added" , G_CALLBACK(add_pad) , sink);
 
	if(! gst_element_link(source , parser)){
		g_warning("linke source to parser failed");
	}
 
	gst_element_set_state(pipeline , GST_STATE_PLAYING);
	printf("Start playing...\n");
	g_main_loop_run(loop);
	printf("Playing stopped!!!\n");
	gst_element_set_state(pipeline , GST_STATE_NULL);
	g_object_unref(pipeline);
}
 
int main(int argc , char *argv[])
{
	if (argc == 2)
	{
		gst_init(&argc , &argv);
		play_file(argv[1]);
	}
 
	return 0;
}
